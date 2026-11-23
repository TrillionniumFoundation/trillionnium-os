package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebMiActionRegion;
import org.trillionnium.hepta.webprotocol.WebObservedNavigation;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;

/**
 * Synthetic unit fixtures against the real v4 receipt, provider, authority and
 * completion classes. URLs/SKUs/amounts below are TEST DATA, never observed Mi
 * pages, phone actions, Binder authentication, model runs or business results.
 */
public final class WebTaskCompositionHostTest {
    private static final String TASK=repeat("1",32),SESSION=repeat("3",64),RUN=repeat("9",32);
    private static final String PACKAGE=WebEvidenceProtocol.HELPER_PACKAGE;
    private static final String GENERATION="22345678-1234-1234-1234-123456789012";
    private static final String OWNER="查一下小米AX3000T的官网售价";
    private static final String FLIGHT="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String DETAIL="https://www.mi.com/shop/buy?product_id=7&cfrom=search";
    private static final String BRIDGE="synthetic_product_link";
    private static final String CARD_MODEL="Xiaomi路由器AX3000T 白色";
    private static final List<String> cases=new ArrayList<String>();
    private static int assertions;
    private interface Work { void run()throws Exception; }
    private static void test(String name,Work body)throws Exception{body.run();cases.add(name);}
    private static void check(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static void rejects(Work body)throws Exception{
        boolean rejected=false;
        try{body.run();}catch(IllegalArgumentException|IllegalStateException|org.json.JSONException expected){rejected=true;}
        check(rejected,"expected exact production boundary rejection");
    }
    private static String repeat(String s,int n){StringBuilder b=new StringBuilder();while(n-->0)b.append(s);return b.toString();}
    private static JSONObject copy(JSONObject o)throws Exception{return new JSONObject(o.toString());}
    private static JSONObject oldFixture(String method)throws Exception{
        Method m=WebFlightEvidenceHostTest.class.getDeclaredMethod(method);m.setAccessible(true);
        try{return (JSONObject)m.invoke(null);}
        catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;}
    }
    private static JSONObject binding(String owner)throws Exception{
        WebTaskPurpose p=WebTaskPurpose.fromOwner(owner);
        JSONObject original=oldFixture("binding");
        return WebEvidenceBinding.fromAttach(new JSONObject().put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("owner",owner).put("owner_sha256",p.ownerSha256).put("contract_sha256",p.contractSha256)
                .put("authorization",new JSONObject(p.authorization.evidence())).put("background",original.getJSONObject("background"))
                .put("controller_identity",original.getJSONObject("controller_identity"))
                .put("helper_identity",original.getJSONObject("helper_identity")));
    }
    private static JSONObject node(String path,String tag,String id,String text)throws Exception{
        JSONObject n=new JSONObject().put("path",path).put("parent_path","0".equals(path)?JSONObject.NULL:path.substring(0,path.lastIndexOf('/')))
                .put("tag",tag).put("id",id).put("text",text);
        for(String k:Arrays.asList("name","role","aria_label","item_type","item_prop","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed"))
            n.put(k,"");
        for(String k:Arrays.asList("disabled","item_scope","hidden_attr","inert_attr","iframe_contents_read"))n.put(k,false);
        n.put("visible_in_viewport",true);
        for(String k:Arrays.asList("href_raw","href_resolved","link_target","value","aria_disabled"))n.put(k,JSONObject.NULL);
        n.put("rect_css_pixels",new JSONArray(new int[]{0,0,1,1}));
        return n;
    }
    private static JSONObject page(String url,JSONArray nodes)throws Exception{
        return oldFixture("dom").put("href",url).put("origin","https://www.mi.com").put("ready_state","complete")
                .put("truncated",false).put("truncation_reasons",new JSONArray()).put("nodes",nodes).put("visited",nodes.length());
    }
    private static JSONObject searchDom()throws Exception{
        JSONArray n=new JSONArray().put(rect(node("0","html","",""),0,0,400,800))
                .put(rect(node("0/0","div","",""),10,100,350,300));
        n.put(rect(node("0/0/0","a",BRIDGE,"AX3000T"),10,100,350,300)
                .put("href_raw","/shop/buy?product_id=7&cfrom=search").put("href_resolved",DETAIL).put("link_target","_blank"));
        n.put(rect(node("0/0/0/1","h2","",CARD_MODEL),20,120,300,150));
        n.put(rect(node("0/0/0/2","span","","199元"),20,180,100,210));
        n.put(rect(node("0/0/0/3","del","",""),110,180,200,210));
        n.put(rect(node("0/0/0/3/0","span","","399元"),110,180,200,210));
        JSONObject dom=page(WebTaskPurpose.fromOwner(OWNER).initialUrl,n);
        dom.put("action_region_observations",regionObservations(dom));
        dom.put("clipping_context_observations",emptyClipObservations());
        return dom;
    }
    private static JSONObject rect(JSONObject node,int left,int top,int right,int bottom)throws Exception{
        return node.put("rect_css_pixels",new JSONArray(new int[]{left,top,right,bottom}));
    }
    private static JSONObject emptyClipObservations()throws Exception{
        return new JSONObject().put("schema","hepta.raw-clip-context-observations.v1")
                .put("candidates",new JSONArray()).put("style_contexts",new JSONArray()).put("complete",true)
                .put("total_context_count",0).put("fully_clipped_inferred",false)
                .put("closed_shadow_contents_inspected",false).put("grants_action_authority",false);
    }
    /** Complete synthetic CSS and hit-test inputs, replayed by the real region parser. */
    private static JSONObject regionObservations(JSONObject dom)throws Exception{
        JSONArray nodes=dom.getJSONArray("nodes"),styles=new JSONArray(),hits=new JSONArray();
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);String path=n.getString("path");int children=0;
            for(int j=0;j<nodes.length();j++)if(path.equals(nodes.getJSONObject(j).opt("parent_path")))children++;
            JSONObject style=new JSONObject().put("path",path).put("element_child_count",children)
                    .put("accessible_shadow_root_present",false).put("closed_shadow_contents_inspected",false);
            for(String key:new String[]{"transform","translate","rotate","scale","perspective","filter","backdrop_filter",
                    "clip_path","mask_image","contain"})style.put(key,"none");
            for(String key:new String[]{"visibility","overflow_x","overflow_y","content_visibility"})style.put(key,"visible");
            style.put("position","static").put("display","block").put("opacity","1").put("overflow_clip_margin","0px")
                    .put("transform_style","flat").put("zoom","1").put("will_change","auto").put("pointer_events","auto")
                    .put("isolation","auto").put("mix_blend_mode","normal");
            for(String key:new String[]{"pseudo_before","pseudo_after"})style.put(key,new JSONObject()
                    .put("content","none").put("display","none").put("visibility","visible").put("opacity","1")
                    .put("position","static").put("transform","none").put("pointer_events","auto"));
            styles.put(style);
        }
        for(String path:new String[]{"0/0/0","0/0/0/1","0/0/0/2","0/0/0/3/0"}){
            JSONObject n=null;for(int i=0;i<nodes.length();i++)if(path.equals(nodes.getJSONObject(i).getString("path")))n=nodes.getJSONObject(i);
            JSONArray r=n.getJSONArray("rect_css_pixels"),points=new JSONArray();
            for(double[] ratio:new double[][]{{.5,.5},{.2,.2},{.8,.2},{.2,.8},{.8,.8}}){
                java.util.LinkedHashSet<String> stack=new java.util.LinkedHashSet<String>();
                stack.add(path);stack.add("0/0/0");stack.add("0/0");stack.add("0");
                points.put(new JSONObject().put("x",r.getDouble(0)+(r.getDouble(2)-r.getDouble(0))*ratio[0])
                        .put("y",r.getDouble(1)+(r.getDouble(3)-r.getDouble(1))*ratio[1]).put("top_path",path)
                        .put("stack_complete",true).put("stack_paths",new JSONArray(stack)));
            }
            hits.put(new JSONObject().put("dom_path",path).put("rect_css_pixels",new JSONArray(r.toString())).put("points",points));
        }
        JSONObject candidate=new JSONObject().put("root_path","0/0").put("anchor_path","0/0/0")
                .put("model_path","0/0/0/1").put("current_price_path","0/0/0/2").put("comparison_price_path","0/0/0/3/0")
                .put("model_label",CARD_MODEL).put("observed_variant","白色")
                .put("href_raw","/shop/buy?product_id=7&cfrom=search").put("href_resolved",DETAIL).put("link_target","_blank")
                .put("current_price_raw","199元").put("comparison_price_raw","399元")
                .put("price_context","search_card_only").put("detail_price_verified",false);
        return new JSONObject().put("schema",WebMiActionRegion.OBS_SCHEMA).put("site_policy_id",WebMiActionRegion.POLICY)
                .put("selection",WebMiActionRegion.SELECTION).put("status","observed").put("candidate_count",1)
                .put("candidate",candidate).put("style_contexts",styles).put("hit_tests",hits)
                .put("foreign_overlap_paths",new JSONArray()).put("visible_modal_paths",new JSONArray())
                .put("special_paint_in_region_paths",new JSONArray()).put("top_layer",new JSONObject()
                        .put("selector_api_available",true).put("modal_paths",new JSONArray()).put("popover_paths",new JSONArray())
                        .put("fullscreen_present",false).put("fullscreen_path",JSONObject.NULL).put("closed_shadow_contents_inspected",false))
                .put("complete",true).put("coordinates_used_for_input",false).put("closed_shadow_contents_inspected",false)
                .put("pixel_visibility_claimed",false);
    }
    private static JSONObject detailDom()throws Exception{
        JSONArray n=new JSONArray().put(node("0","html","","")).put(node("0/0","main","",""))
                .put(node("0/0/0","section","","").put("item_scope",true).put("item_type","https://schema.org/Product"))
                .put(node("0/0/0/0","h1","","AX3000T").put("item_prop","name"))
                .put(node("0/0/0/1","div","","").put("item_scope",true).put("item_type","https://schema.org/Offer").put("item_prop","offers"))
                .put(node("0/0/0/1/0","span","","199.00").put("item_prop","price"))
                .put(node("0/0/0/1/1","span","","CNY").put("item_prop","priceCurrency"));
        return page(DETAIL,n);
    }
    private static PhoneObservation.Node ax(String id,String view,String label,int y,boolean clickable,boolean enabled)throws Exception{
        if(BRIDGE.equals(view))return nativeNode(id,"android.view.View","",
                ("AX3000T".equals(label)?CARD_MODEL:label)+" 199元 399元",new Rect(200,y,550,y+60),
                clickable,enabled,"0/0/"+id.substring(1));
        return legacyAx(id,view,label,y,clickable,enabled);
    }
    /** Frozen old resource-ID shape: intentionally lacks the current native ancestry. */
    private static PhoneObservation.Node legacyAx(String id,String view,String label,int y,boolean clickable,boolean enabled)throws Exception{
        return new PhoneObservation.Node(id,PACKAGE,"android.view.View",view,label,"",new Rect(200,y,550,y+60),
                clickable,false,false,enabled,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,
                WebEvidenceJson.sha("synthetic AX "+id+" "+view+" "+label+" "+y));
    }
    private static PhoneObservation.Node nativeNode(String id,String cls,String text,String description,Rect bounds,
            boolean clickable,boolean enabled,String path)throws Exception{
        return new PhoneObservation.Node(id,PACKAGE,cls,"",text,description,bounds,clickable,false,false,enabled,false,false,
                ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),
                ObservedImeEnter.UNKNOWN,null,false,WebEvidenceJson.sha("synthetic current native "+id+" "+path),path,"android.view.View");
    }
    private static PhoneObservation frame(String id,long clock,int window,List<PhoneObservation.Node> nodes)throws Exception{
        List<PhoneObservation.Node> complete=new ArrayList<PhoneObservation.Node>(nodes);
        complete.add(nativeNode("n999999","android.webkit.WebView","","",new Rect(0,400,1200,2800),false,true,"0"));
        for(PhoneObservation.Node n:nodes)if(n.nativeTreePath!=null){
            String model=n.description.substring(0,n.description.length()-" 199元 399元".length());int y=n.bounds.top;
            complete.add(nativeNode(n.id+"1","android.widget.TextView",model,"",new Rect(210,y+5,500,y+25),true,n.enabled,n.nativeTreePath+"/1"));
            complete.add(nativeNode(n.id+"2","android.widget.TextView","199元","",new Rect(210,y+30,320,y+50),false,n.enabled,n.nativeTreePath+"/2/0"));
            complete.add(nativeNode(n.id+"3","android.view.View"," 399元","",new Rect(330,y+30,500,y+50),false,n.enabled,n.nativeTreePath+"/2/1"));
        }
        int text=0;for(PhoneObservation.Node n:complete)text+=n.text.length()+n.description.length();
        PhoneObservation.CollectionStats stats=new PhoneObservation.CollectionStats(4096,512,200000,
                complete.size(),complete.size(),text,0,0,0,0,1);
        JSONObject selection=new JSONObject().put("mode","background").put("allowed_packages",new JSONArray().put(PACKAGE))
                .put("bootstrap_package",PACKAGE).put("bootstrap_source","owner_selected_initial_app")
                .put("bootstrap_model_issued",false).put("home_allowed",false).put("main_display_fallback",false);
        return new PhoneObservation(id,PACKAGE,clock,1200,2800,0,window,new Rect(0,0,1200,2800),null,
                WebEvidenceJson.sha("synthetic app tree "+id),WebEvidenceJson.sha("synthetic screen "+id),
                new ObservationState(WebEvidenceJson.sha("synthetic state "+id),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1200,2800},"android.widget.FrameLayout",1,7,
                        new int[]{0,0,1200,2800},"owned helper"),false,complete,GENERATION,PACKAGE,Collections.singletonList(PACKAGE),
                stats,selection,WebTaskPurpose.fromOwner(OWNER).ownerSha256);
    }
    private static PhoneObservation searchFrame()throws Exception{
        return frame(repeat("2",32),1005,19,Arrays.asList(ax("n1",BRIDGE,"AX3000T",600,true,true)));
    }
    private static PhoneObservation detailFrame()throws Exception{
        return frame(repeat("5",32),1205,19,Arrays.asList(ax("n2","","AX3000T",600,false,true),
                ax("n3","","199.00",700,false,true),ax("n4","","CNY",800,false,true)));
    }
    private static JSONObject request(long epoch)throws Exception{
        return oldFixture("request").put("expected_navigation_epoch",epoch)
                .put("request_nonce",repeat(epoch==7?"4":"6",64));
    }
    private static JSONObject rawCapture(JSONObject b,JSONObject dom,long epoch,long start)throws Exception{
        // Synthetic fixture completion only, including retained query factories.
        // Keep supplied values and negative mutations; derive membership counts
        // from this fixture's complete node array after the v4 card expansion.
        dom=copy(dom);dom.put("schema",WebDomStability.DOM_SCHEMA);
        if(!dom.has("truncation_reasons"))dom.put("truncation_reasons",new JSONArray());
        JSONArray rows=dom.getJSONArray("nodes");dom.put("visited",rows.length());
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);
            for(String key:new String[]{"tag","id","name","role","aria_label","aria_hidden","aria_modal","aria_selected",
                    "aria_checked","aria_pressed","text","item_type","item_prop"})if(!n.has(key))n.put(key,"");
            for(String key:new String[]{"visible_in_viewport","disabled","hidden_attr","inert_attr","item_scope","iframe_contents_read"})
                if(!n.has(key))n.put(key,false);
            for(String key:new String[]{"href_raw","href_resolved","link_target","value","aria_disabled"})if(!n.has(key))n.put(key,JSONObject.NULL);
            if(!n.has("rect_css_pixels"))n.put("rect_css_pixels",new JSONArray(new int[]{0,0,1,1}));
        }
        JSONObject raw=oldFixture("captured"),req=request(epoch),c=raw.getJSONObject("capture");
        String requestRaw=req.toString(),domRaw=dom.toString();long delta=start-1000;
        raw.put("request_json_utf8",requestRaw).put("request_sha256",WebEvidenceJson.sha(requestRaw))
                .put("binding",copy(b)).put("binding_sha256",WebEvidenceBinding.sha256(b))
                .put("controller_identity",copy(b.getJSONObject("controller_identity")))
                .put("helper_identity",copy(b.getJSONObject("helper_identity")));
        raw.getJSONObject("storage_isolation").put("first_url",b.get("initial_url"));
        c.put("binding",copy(b)).put("challenge",req.get("request_nonce")).put("navigation_epoch",epoch)
                .put("committed_main_frame_url",dom.get("href")).put("current_native_url",dom.get("href"))
                .put("commit_elapsed_ms",start-50).put("started_elapsed_ms",start).put("ended_elapsed_ms",start+10)
                .put("dom_raw_utf8",domRaw).put("dom_sha256",WebEvidenceJson.sha(domRaw));
        JSONArray samples=c.getJSONObject("capture_geometry").getJSONArray("samples");
        for(int i=0;i<samples.length();i++){
            JSONObject n=samples.getJSONObject(i).getJSONObject("native");
            n.put("sampled_elapsed_ms",n.getLong("sampled_elapsed_ms")+delta)
                    .put("scale_changed_elapsed_ms",n.getLong("scale_changed_elapsed_ms")+delta);
        }
        WebDomStability.Result stable=WebDomStability.evaluate(domRaw,domRaw,b.getString("site_policy_id"));
        String stableSha=WebDomCanonical.sha256(stable.evidence());
        c.put("before_dom_raw_utf8",domRaw).put("before_dom_sha256",WebEvidenceJson.sha(domRaw))
                .put("dom_stability",stable.evidence()).put("dom_stability_sha256",stableSha)
                .put("raw_dom_equal",stable.rawEqual).put("comparison_scope",stable.comparisonScope)
                .put("observed_link_navigation",JSONObject.NULL);
        c.getJSONObject("capture_geometry").put("dom_equal_across_visual_callback",stable.rawEqual)
                .put("dom_comparison_scope",stable.comparisonScope).put("dom_stability_sha256",stableSha);
        return raw;
    }
    private static WebEvidenceReceipt receipt(JSONObject b,JSONObject raw)throws Exception{
        JSONObject req=new JSONObject(raw.getString("request_json_utf8")),c=raw.getJSONObject("capture");
        byte[] bytes=(raw.toString()+"\n").getBytes(StandardCharsets.UTF_8);
        JSONObject cb=callback(b,req).put("status","captured").put("navigation_epoch",c.get("navigation_epoch"))
                .put("raw_length",bytes.length).put("raw_sha256",WebEvidenceJson.sha(bytes));
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,cb.toString(),bytes,10484,1000,1500);
    }
    private static JSONObject callback(JSONObject b,JSONObject req)throws Exception{
        return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method","captureEvidence")
                .put("request_nonce",req.get("request_nonce")).put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("status","unavailable").put("reason","synthetic_unit_fixture").put("actual_helper_uid",10484)
                .put("actual_display_id",7).put("actual_window_id",19).put("webview_instance",req.get("expected_webview_instance"))
                .put("navigation_epoch",req.get("expected_navigation_epoch")).put("binding_sha256",WebEvidenceBinding.sha256(b))
                .put("raw_length",0).put("raw_sha256",JSONObject.NULL).put("retired",false)
                .put("cleanup",JSONObject.NULL).put("recovery",JSONObject.NULL);
    }
    private static WebTaskDomain observed(JSONObject b,JSONObject dom,long epoch,long time,PhoneObservation frame)throws Exception{
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);
        JSONObject raw=rawCapture(b,dom,epoch,time);
        if(p.shopping!=null&&WebSitePolicy.forShopping(p.shopping).classify(dom.getString("href"))==WebSitePolicy.Route.PUBLIC_DETAIL_CANDIDATE){
            JSONObject source=rawCapture(b,searchDom(),7,1000).getJSONObject("capture");
            raw.getJSONObject("capture").put("observed_link_navigation",navigationFixture(armFixture(b,source)));
        }
        WebTaskDomain domain=WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),frame,receipt(b,raw),b);
        if(p.shopping!=null&&!domain.clickIds.isEmpty())domain=domain.withObservedLinkArm(armFixture(b,raw.getJSONObject("capture")));
        return domain;
    }
    /** The synthetic request is replayed by the production ARM constructor and verifier. */
    private static JSONObject armFixture(JSONObject binding,JSONObject source)throws Exception{
        WebDomStability.Result stable=WebDomStability.verify(source.getString("before_dom_raw_utf8"),source.getString("dom_raw_utf8"),
                binding.getString("site_policy_id"),source.getJSONObject("dom_stability"));
        if(stable.region==null)throw new IllegalArgumentException("synthetic ARM requires a complete valid source region");
        JSONObject request=new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ARM_OBSERVED_LINK))
                .put("task_id",binding.get("task_id")).put("controller_session_nonce",binding.get("controller_session_nonce"))
                .put("request_nonce",repeat("a",64)).put("deadline_elapsed_ms",2000)
                .put("expected_webview_instance",source.get("webview_instance")).put("expected_navigation_epoch",source.get("navigation_epoch"))
                .put("source_capture_challenge",source.get("challenge")).put("source_dom_sha256",source.get("dom_sha256"))
                .put("source_stability_sha256",source.get("dom_stability_sha256")).put("anchor_dom_path",stable.region.anchorPath)
                .put("model_run_id",RUN);
        JSONObject arm=WebObservedNavigation.arm(request,binding,source,1050);
        return WebObservedNavigation.verifyArm(request,binding,source,arm);
    }
    /** Unit callback facts only; never actual Binder, native action, or network evidence. */
    private static JSONObject navigationFixture(JSONObject arm)throws Exception{
        JSONObject profile=new JSONObject().put("profile_assignment_api","WebViewCompat.setProfile")
                .put("profile_assigned_before_other_interactions",true).put("actual_profile_name",arm.get("storage_profile_name"))
                .put("profile_assigned_elapsed_ms",1101).put("reused_same_lease_profile",true).put("network_loads_blocked",true)
                .put("javascript_enabled",false).put("visible_in_layout",false);
        return new JSONObject().put("schema",WebObservedNavigation.NAV_SCHEMA).put("arm",copy(arm))
                .put("popup_callback_observed",true).put("popup_callback_elapsed_ms",1100).put("popup_is_dialog",false)
                .put("popup_is_user_gesture",true).put("popup_url_observed",true).put("popup_url_observed_elapsed_ms",1102)
                .put("popup_observed_url",arm.get("observed_href_resolved")).put("popup_observed_method","GET")
                .put("popup_observed_main_frame",true).put("popup_initiating_frame_verified",false)
                .put("auxiliary_network_loads_blocked",true).put("auxiliary_view_created",true).put("auxiliary_view_destroyed",true)
                .put("same_profile_assignment",profile).put("auxiliary_destroyed_elapsed_ms",1103)
                .put("same_lease_main_load_invoked",true).put("same_lease_main_load_returned",true)
                .put("main_load_begin_elapsed_ms",1104).put("main_load_returned_elapsed_ms",1105)
                .put("new_visible_window_created",false).put("external_app_launched",false).put("transaction_authority",false)
                .put("business_verified",false).put("cancelled",false).put("cancelled_elapsed_ms",JSONObject.NULL)
                .put("cancellation_reason",JSONObject.NULL);
    }
    private static WebTaskDomain waiting(JSONObject b)throws Exception{
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);JSONObject req=request(7),cb=callback(b,req);
        WebEvidenceReceipt r=WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,cb.toString(),null,10484,1000,1500);
        return WebTaskDomain.waiting(TASK,p,p.authorization.bind(TASK),searchFrame(),r,b);
    }
    private static ActionDecision action(String observation,String kind,String node,String status)throws Exception{
        JSONObject raw=new JSONObject().put("action",kind).put("observation_id",observation).put("package",PACKAGE);
        if("click".equals(kind))raw.put("node_id",node).put("node_label","AX3000T");
        if("wait".equals(kind))raw.put("duration_ms",100);
        if("done".equals(kind))raw.put("status",status).put("summary","synthetic fixture only");
        return ActionDecision.parse(raw.toString());
    }
    private static NotesCompletionEvidence.Frame completionFrame(String observation,int window){
        return new NotesCompletionEvidence.Frame(observation,PACKAGE,window,7,GENERATION,1,true,false,
                Collections.<NotesCompletionEvidence.Node>emptyList());
    }
    private static WebShoppingDomain.Navigation navigate(WebTaskDomain before,WebTaskDomain after,boolean accepted,
            boolean dispatched,boolean stale,long start,long end)throws Exception{
        return WebShoppingDomain.Navigation.confirm(before.shopping,after.shopping,action(before.observationId,"click","n1",null),
                RUN,accepted,dispatched,stale,start,end);
    }
    private static Set<String> tools(){return new HashSet<String>(Arrays.asList("open","click","type","submit","back","scroll","wait","done"));}

    public static void main(String[] argv)throws Exception{
        check(argv.length==1,"one create-only report path");
        final JSONObject b=binding(OWNER);
        final WebTaskDomain before=observed(b,searchDom(),7,1000,searchFrame());
        final WebTaskDomain after=observed(b,detailDom(),8,1200,detailFrame());
        final WebShoppingDomain.Navigation actualFixtureNavigation=navigate(before,after,true,true,false,1100,1101);
        final WebTaskDomain linked=after.withNavigation(actualFixtureNavigation);
        test("v3_receipt_and_real_composition",()->{
            check(WebEvidenceProtocol.HELPER_VERSION_CODE==7&&before.shopping!=null&&before.flight==null,"explicit current peer/provider");
            check(before.clickIds.equals(Collections.singleton("n1")),"only actual synthetic same-frame AX id");
            check(!before.resultReady()&&!after.resultReady(),"no result before accepted navigation");
            check(linked.resultReady(),"valid typed fixture connects both real providers");
            check(Boolean.FALSE.equals(linked.resultRecord().get("business_verified"))&&
                    Boolean.FALSE.equals(linked.resultRecord().get("final_native_and_cleanup_gates_verified")),"unit/provider proof is not overall completion");
        });
        test("price_not_filled_from_goal",()->check("199.00".equals(linked.resultRecord().get("amount_decimal"))&&
                "CNY".equals(linked.resultRecord().get("currency")),"actual synthetic data, not goal default"));
        test("result_record_requires_navigation",()->rejects(()->after.resultRecord()));
        test("current_tcg_real_provider_path",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));
            NotesCompletionEvidence.Frame f=completionFrame(linked.observationId,19);gate.observed(f);gate.bindWebDomain(linked);
            check(gate.verified(f),"real Web TCG does not use Notes installed field");
            check(!gate.successClaim(1,RUN,f,false).verified,"unstable final observation rejected");
            check(gate.successClaim(2,RUN,f,true).verified,"pure fixture completes only component gates");
            gate.clearWebDomain();check(!gate.verified(f),"clearing domain clears eligibility");
        });
        test("tcg_no_navigation_cannot_complete",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));
            NotesCompletionEvidence.Frame f=completionFrame(after.observationId,19);gate.observed(f);gate.bindWebDomain(after);
            check(!gate.successClaim(1,RUN,f).verified,"model success cannot replace navigation");
        });
        test("tcg_rejects_stale_observation",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));
            NotesCompletionEvidence.Frame f=completionFrame(linked.observationId,19);gate.observed(f);gate.bindWebDomain(linked);
            check(!gate.verified(completionFrame(repeat("7",32),19)),"old DOM cannot certify new frame");
            check(!gate.verified(completionFrame(linked.observationId,20)),"window identity retained");
            gate.invalidateInstalled("unit_current_identity_changed");check(!gate.verified(f),"current identity invalidation still blocks");
        });
        test("tcg_rejects_other_owner",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,FLIGHT,TaskAuthorization.parse(FLIGHT));rejects(()->gate.bindWebDomain(linked));
        });
        test("wait_has_no_action_capability",()->{
            WebTaskDomain pending=waiting(b);check(pending.clickIds.isEmpty()&&pending.toolMask(tools()).equals(new HashSet<String>(Arrays.asList("wait","done"))),"wait-only");
            check(!pending.resultReady(),"no price or navigation");pending.requireCurrent(action(pending.observationId,"wait",null,null));
            pending.requireCurrent(action(pending.observationId,"done",null,"partial"));
            rejects(()->pending.requireCurrent(action(pending.observationId,"done",null,"success")));
            rejects(()->pending.requireCurrent(action(pending.observationId,"click","n1",null)));
        });
        test("flight_wait_uses_original_natural_owner",()->{
            WebTaskDomain pending=waiting(binding(FLIGHT));
            check(pending.flight!=null&&pending.shopping==null&&!pending.resultReady(),"independent flight provider; no result provider fabricated");
        });
        test("original_tool_mask_is_intersection",()->{
            check(before.toolMask(Collections.singleton("wait")).equals(Collections.singleton("wait")),"no click if original authority lacks it");
            check(before.edits(Collections.singleton("n1")).isEmpty()&&before.openPackages(Collections.singleton(PACKAGE)).isEmpty(),"no type/open expansion");
            rejects(()->before.requireCurrent(ActionDecision.parse(new JSONObject().put("action","click").put("observation_id",before.observationId)
                    .put("package",PACKAGE).put("x",100).put("y",100).toString())));
        });
        test("missing_accepted_outcome_rejected",()->rejects(()->navigate(before,after,false,true,false,1100,1101)));
        test("missing_dispatch_outcome_rejected",()->rejects(()->navigate(before,after,true,false,false,1100,1101)));
        test("stale_native_outcome_rejected",()->rejects(()->navigate(before,after,true,true,true,1100,1101)));
        for(final long[] pair:new long[][]{{1009,1101},{1102,1101},{1100,1201}}){
            test("dispatch_time_order_"+pair[0]+"_"+pair[1],()->rejects(()->navigate(before,after,true,true,false,pair[0],pair[1])));
        }
        test("operator_without_native_run_rejected",()->rejects(()->WebShoppingDomain.Navigation.confirm(before.shopping,after.shopping,
                action(before.observationId,"click","n1",null),null,true,true,false,1100,1101)));
        test("old_source_observation_rejected",()->rejects(()->WebShoppingDomain.Navigation.confirm(before.shopping,after.shopping,
                action(repeat("7",32),"click","n1",null),RUN,true,true,false,1100,1101)));
        test("new_epoch_required",()->{
            WebTaskDomain same=observed(b,detailDom(),7,1200,detailFrame());rejects(()->navigate(before,same,true,true,false,1100,1101));
        });
        test("source_link_target_must_match",()->{
            JSONObject dom=detailDom().put("href",DETAIL.replace("product_id=7","product_id=78"));WebTaskDomain other=observed(b,dom,8,1200,detailFrame());
            rejects(()->navigate(before,other,true,true,false,1100,1101));
        });
        test("navigation_cannot_cross_lease",()->{
            JSONObject other=copy(b).put("controller_session_nonce",repeat("8",64)).put("storage_profile_name","hepta_v2_"+repeat("8",64));
            WebTaskPurpose p=WebTaskPurpose.requireBinding(other);check(!p.ownerSha256.isEmpty(),"same owner can have distinct lease");
            rejects(()->WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),detailFrame(),receipt(b,rawCapture(b,detailDom(),8,1200)),other));
        });
        test("code3_binding_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("helper_identity").put("version_code",3);rejects(()->waiting(bad));
        });
        test("old_v2_binding_rejected",()->rejects(()->waiting(copy(b).put("schema","hepta.web-helper.binding.v2"))));
        test("foreign_site_policy_rejected",()->rejects(()->waiting(copy(b).put("site_policy_id","csair_public_flight_v1"))));
        test("foreign_compiled_initial_url_rejected",()->rejects(()->waiting(copy(b).put("initial_url","https://m.csair.com/"))));
        test("mutated_authority_evidence_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("authorization").put("authorization_sha256",repeat("0",64));rejects(()->waiting(bad));
        });
        test("extra_selected_app_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("background").getJSONArray("selected_packages").put("com.android.settings");rejects(()->waiting(bad));
        });
        test("wrong_authenticated_uid_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("helper_identity").put("uid",10485);rejects(()->waiting(bad));
        });
        test("raw_controller_identity_mismatch_rejected",()->{
            JSONObject raw=rawCapture(b,searchDom(),7,1000);raw.getJSONObject("controller_identity").put("uid",10482);rejects(()->receipt(b,raw));
        });
        test("callback_metadata_lost_binding_rejected",()->{
            JSONObject req=request(7),cb=callback(b,req).put("binding_sha256",JSONObject.NULL);
            rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,cb.toString(),null,10484,1000,1500));
        });
        test("bound_dom_wrong_origin_rejected",()->{
            JSONObject dom=searchDom().put("origin","https://m.mi.com");rejects(()->observed(b,dom,7,1000,searchFrame()));
        });
        test("manual_diagnostic_not_task_evidence",()->{
            JSONObject raw=rawCapture(b,searchDom(),7,1000).put("diagnostic_unbound",true);rejects(()->receipt(b,raw));
        });
        test("duplicate_native_card_description_blocks_even_disabled",()->{
            PhoneObservation f=frame(repeat("2",32),1005,19,Arrays.asList(ax("n1",BRIDGE,"AX3000T",600,true,true),
                    ax("n9",BRIDGE,"AX3000T",800,true,false)));
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"all card descriptions counted before state filtering");
        });
        test("legacy_nonempty_resource_id_fixture_is_rejected",()->{
            PhoneObservation f=frame(repeat("2",32),1005,19,Arrays.asList(legacyAx("n1",BRIDGE,"AX3000T",600,true,true)));
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"frozen old resource-ID shape cannot replace the current native card bridge");
        });
        test("out_of_screen_native_node_has_no_css_fallback",()->{
            PhoneObservation f=frame(repeat("2",32),1005,19,Arrays.asList(ax("n1",BRIDGE,"AX3000T",50,true,true)));
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"native rectangle outside actual WebView");
        });
        test("different_native_label_blocks_product_link",()->{
            PhoneObservation f=frame(repeat("2",32),1005,19,Arrays.asList(ax("n1",BRIDGE,"AX3000",600,true,true)));
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"same id is insufficient");
        });
        test("duplicate_dom_id_blocks_product_link",()->{
            JSONObject dom=searchDom();dom.getJSONArray("nodes").put(node("0/0/1","div",BRIDGE,"").put("hidden_attr",true));
            dom.put("visited",4);check(observed(b,dom,7,1000,searchFrame()).clickIds.isEmpty(),"hidden duplicate id counts");
        });
        test("transaction_anchor_mints_no_capability",()->{
            JSONObject dom=searchDom();dom.getJSONArray("nodes").put(node("0/0/0/0","span","","购买"));dom.put("visited",4);
            check(observed(b,dom,7,1000,searchFrame()).clickIds.isEmpty(),"no purchase path");
        });
        test("modal_blocks_all_capabilities",()->{
            JSONObject dom=searchDom();dom.getJSONArray("nodes").put(node("0/0/1","div","","同意").put("role","dialog"));dom.put("visited",4);
            check(observed(b,dom,7,1000,searchFrame()).clickIds.isEmpty(),"consent not silently dismissed");
        });
        test("conditional_price_cannot_complete",()->{
            JSONObject dom=detailDom();dom.getJSONArray("nodes").put(node("0/0/0/2","span","","限时优惠"));dom.put("visited",8);
            WebTaskDomain conditional=observed(b,dom,8,1200,detailFrame());
            check(!conditional.withNavigation(navigate(before,conditional,true,true,false,1100,1101)).resultReady(),"conditional is not exact public price");
        });
        test("starting_price_cannot_complete",()->{
            JSONObject dom=detailDom();dom.getJSONArray("nodes").put(node("0/0/0/2","span","","起"));dom.put("visited",8);
            WebTaskDomain starting=observed(b,dom,8,1200,detailFrame());
            check(!starting.withNavigation(navigate(before,starting,true,true,false,1100,1101)).resultReady(),"starting price rejected");
        });
        test("currency_requires_actual_native_label",()->{
            PhoneObservation f=frame(repeat("5",32),1205,19,Arrays.asList(ax("n2","","AX3000T",600,false,true),ax("n3","","199.00",700,false,true)));
            WebTaskDomain missing=observed(b,detailDom(),8,1200,f);
            check(!missing.withNavigation(navigate(before,missing,true,true,false,1100,1101)).resultReady(),"DOM currency cannot replace native readback");
        });
        test("native_duplicate_amount_blocks_result",()->{
            PhoneObservation f=frame(repeat("5",32),1205,19,Arrays.asList(ax("n2","","AX3000T",600,false,true),
                    ax("n3","","199.00",700,false,true),ax("n4","","CNY",800,false,true),ax("n8","","199.00",900,false,false)));
            WebTaskDomain ambiguous=observed(b,detailDom(),8,1200,f);
            check(!ambiguous.withNavigation(navigate(before,ambiguous,true,true,false,1100,1101)).resultReady(),"disabled duplicate still ambiguous");
        });
        test("wrong_dom_currency_cannot_complete",()->{
            JSONObject dom=detailDom();dom.getJSONArray("nodes").getJSONObject(6).put("text","USD");
            WebTaskDomain wrong=observed(b,dom,8,1200,detailFrame());
            check(!wrong.withNavigation(navigate(before,wrong,true,true,false,1100,1101)).resultReady(),"CNY is observed, never inferred from goal");
        });
        JSONObject report=new JSONObject().put("schema","hepta.v54-web-task-composition-host.v1").put("all_pass",true)
                .put("cases",cases.size()).put("assertions",assertions).put("case_names",new JSONArray(cases))
                .put("fixture_kind","synthetic DOM/AX/clock/PM and native-outcome values against actual production code")
                .put("actual_mi_dom_seen",false).put("actual_model_run_executed",false).put("binder_authenticated",false)
                .put("phone_commands_executed",0).put("actual_shopping_or_flight_result_verified",false)
                .put("business_verified",false).put("final_native_and_cleanup_gates_verified",false);
        Files.write(Paths.get(argv[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("WEB_TASK_COMPOSITION_CASES="+cases.size());
        System.out.println("WEB_TASK_COMPOSITION_ASSERTIONS="+assertions);
    }
}
