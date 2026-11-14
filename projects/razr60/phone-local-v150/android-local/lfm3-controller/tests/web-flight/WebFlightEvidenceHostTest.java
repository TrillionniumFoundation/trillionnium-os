package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebRecoveryPolicy;
import org.trillionnium.hepta.webprotocol.WebStorageEvidence;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebObservedNavigation;

/** Real pure production classes; synthetic native geometry/AX and callback identity.
 * The Rect fixture is explicitly Android IO. No phone, Binder authentication,
 * proprietary model or flight-query success is established by these cases. */
public final class WebFlightEvidenceHostTest {
    private static final String TASK="11111111111111111111111111111111";
    private static final String OBS="22222222222222222222222222222222";
    private static final String SESSION=repeat("3",64),NONCE=repeat("4",64);
    private static final String INSTANCE="12345678-1234-1234-1234-123456789012";
    private static final String GENERATION="22345678-1234-1234-1234-123456789012";
    private static final String PACKAGE=WebEvidenceProtocol.HELPER_PACKAGE;
    private static int assertions;
    private static final List<String> names=new ArrayList<String>();
    private interface Case { void run()throws Exception; }
    private interface Change { void change(JSONObject value)throws Exception; }
    private static void test(String name,Case work)throws Exception{work.run();names.add(name);}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void rejects(Case work)throws Exception{
        boolean rejected=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException|org.json.JSONException expected){rejected=true;}
        check(rejected,"expected exact boundary rejection");
    }
    private static String repeat(String value,int count){StringBuilder out=new StringBuilder();while(count-->0)out.append(value);return out.toString();}
    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}

    private static JSONObject dom()throws Exception{
        JSONObject root=new JSONObject().put("path","0").put("parent_path",JSONObject.NULL).put("tag","html")
                .put("rect_css_pixels",new JSONArray(new int[]{0,0,400,800}));
        for(String key:new String[]{"id","name","role","aria_label","aria_hidden","aria_modal","aria_selected",
                "aria_checked","aria_pressed","text","item_type","item_prop"})root.put(key,"");
        for(String key:new String[]{"disabled","hidden_attr","inert_attr","item_scope","iframe_contents_read"})root.put(key,false);
        root.put("visible_in_viewport",true);
        for(String key:new String[]{"href_raw","href_resolved","link_target","value","aria_disabled"})root.put(key,JSONObject.NULL);
        return new JSONObject().put("schema",WebDomStability.DOM_SCHEMA).put("geometry_semantics_verified",false)
                .put("href","https://m.csair.com/").put("origin","https://m.csair.com").put("ready_state","complete")
                .put("truncated",false).put("truncation_reasons",new JSONArray()).put("nodes",new JSONArray().put(root)).put("visited",1)
                .put("visual_viewport",new JSONObject().put("width",400).put("height",800).put("offset_left",0)
                        .put("offset_top",0).put("page_left",0).put("page_top",0).put("scale",1))
                .put("viewport_css_pixels",new JSONArray(new int[]{400,800}))
                .put("layout_viewport_css_pixels",new JSONArray(new int[]{400,800}))
                .put("document_scroll_css_pixels",new JSONArray(new int[]{0,0}))
                .put("document_extent_css_pixels",new JSONArray(new int[]{400,1200}));
    }
    private static JSONObject geometryCapture()throws Exception{
        JSONArray samples=new JSONArray();String[] phases={"before_js1","after_js1","before_js2","after_js2"};
        for(int i=0;i<4;i++){
            JSONObject state=new JSONObject().put("sampled_elapsed_ms",1001+i).put("display_id",7).put("actual_window_id",19)
                    .put("bounds_screen_pixels",new JSONArray(new int[]{0,400,1200,2800}))
                    .put("global_visible_rect_pixels",new JSONArray(new int[]{0,250,1200,2650}))
                    .put("global_visible_rect_source","View.getGlobalVisibleRect; root-view coordinates")
                    .put("scroll_pixels",new JSONArray(new int[]{0,0})).put("padding_pixels",new JSONArray(new int[]{0,0,0,0}))
                    .put("view_transform",new JSONArray(new double[]{1,1,0,0,0})).put("webview_get_scale",2.75)
                    .put("scale_change_sequence",1).put("scale_changed_elapsed_ms",999)
                    .put("scale_callback_old",1.0).put("scale_callback_new",2.75)
                    .put("use_wide_viewport",true).put("load_with_overview_mode",true);
            samples.put(new JSONObject().put("phase",phases[i]).put("native",state));
        }
        JSONObject capture=new JSONObject().put("display_id",7).put("actual_window_id",19).put("started_elapsed_ms",1000)
                .put("ended_elapsed_ms",1010).put("webview_bounds_screen_pixels",new JSONArray(new int[]{0,400,1200,2800}))
                .put("capture_geometry",new JSONObject().put("schema",WebNativeGeometry.SCHEMA).put("samples",samples)
                        .put("native_samples_equal",true).put("dom_equal_across_visual_callback",true).put("ui_thread_bracket",true)
                        .put("get_scale_is_deprecated_racy_observation",true).put("css_to_screen_mapping_verified",false));
        return wireFixtureStability(capture,dom(),captureBinding());
    }
    /** Both raw values are synthetic; the real shared verifier derives every proof/hash. */
    private static JSONObject wireFixtureStability(JSONObject capture,JSONObject dom,JSONObject binding)throws Exception{
        String raw=dom.toString();WebDomStability.Result proof=WebDomStability.evaluate(raw,raw,binding.getString("site_policy_id"));
        String proofSha=WebDomCanonical.sha256(proof.evidence());
        capture.put("binding",copy(binding)).put("dom_raw_utf8",raw).put("dom_sha256",WebEvidenceJson.sha(raw))
                .put("before_dom_raw_utf8",raw).put("before_dom_sha256",WebEvidenceJson.sha(raw))
                .put("dom_stability",proof.evidence()).put("dom_stability_sha256",proofSha)
                .put("raw_dom_equal",proof.rawEqual).put("comparison_scope",proof.comparisonScope)
                .put("observed_link_navigation",JSONObject.NULL);
        capture.getJSONObject("capture_geometry").put("dom_equal_across_visual_callback",proof.rawEqual)
                .put("dom_comparison_scope",proof.comparisonScope).put("dom_stability_sha256",proofSha);
        return capture;
    }
    private static JSONObject state(JSONObject capture,int sample)throws Exception{
        return capture.getJSONObject("capture_geometry").getJSONArray("samples").getJSONObject(sample).getJSONObject("native");
    }
    private static void badGeometry(String name,Change change)throws Exception{
        test(name,()->{JSONObject c=geometryCapture();change.change(c);rejects(()->WebNativeGeometry.read(c,dom(),7,19));});
    }

    private static final class Tree {
        final String text,signature;final boolean interactive;final List<Tree> children;
        Tree(String text,boolean interactive,Tree...children)throws Exception{
            this.text=text;this.interactive=interactive;this.children=Arrays.asList(children);
            signature=WebEvidenceJson.sha("synthetic AX source\n"+text+"\n"+interactive+"\n"+this.children.size());
        }
    }
    private static ObservedChildText.Result child(final String...texts)throws Exception{
        Tree[] leaves=new Tree[texts.length];for(int i=0;i<texts.length;i++)leaves[i]=new Tree(texts[i],false);
        final Tree root=new Tree("",true,leaves);
        return ObservedChildText.collect(root,new ObservedChildText.Reader<Tree>(){
            public ObservedChildText.Metadata metadata(Tree n){return new ObservedChildText.Metadata(true,true,n==root,n==root,false,false,n.interactive);}
            public String text(Tree n){return n.text;}public String description(Tree n){return "";}
            public String identity(Tree n){return n.signature;}public String viewId(Tree n){return "";}
            public int childCount(Tree n){return n.children.size();}public Tree child(Tree n,int i){return n.children.get(i);}
            public void release(Tree n){}
        });
    }
    private static PhoneObservation.Node node(String id,String resource,String pkg,String type,String own,Rect box,
            boolean clickable,boolean enabled,boolean editable,boolean password,boolean scrollable,
            ObservedChildText.Result child,String signature)throws Exception{
        String actual=signature==null?child.bind(child.rootSignature.isEmpty()?WebEvidenceJson.sha("synthetic own node"):child.rootSignature):signature;
        return new PhoneObservation.Node(id,pkg,type,resource,own,"",box,clickable,editable,scrollable,enabled,false,password,
                child,ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,actual);
    }
    private static PhoneObservation.Node field(String id,String resource,ObservedChildText.Result child)throws Exception{
        return node(id,resource,PACKAGE,"android.view.View","",new Rect(200,600,550,800),true,true,false,false,false,child,null);
    }
    private static PhoneObservation frame(List<PhoneObservation.Node> nodes,int[] root,int[] window){
        return new PhoneObservation(OBS,PACKAGE,1005,1200,2800,0,19,new Rect(0,0,1200,2800),null,repeat("a",64),repeat("b",64),
                new ObservationState(repeat("c",64),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(root,"android.widget.FrameLayout",1,7,window,"owned helper"),false,nodes,
                GENERATION,PACKAGE,Collections.singletonList(PACKAGE));
    }
    private static PhoneObservation frame(PhoneObservation.Node...nodes){return frame(Arrays.asList(nodes),
            new int[]{0,0,1200,2800},new int[]{0,0,1200,2800});}
    private static PhoneObservation.Node match(PhoneObservation frame,String id,String type,String label,List<String> texts,boolean derived)throws Exception{
        Method m=WebFlightDomain.class.getDeclaredMethod("uniqueNative",PhoneObservation.class,WebNativeGeometry.class,
                String.class,String.class,String.class,List.class,boolean.class);
        m.setAccessible(true);
        try{return (PhoneObservation.Node)m.invoke(null,frame,WebNativeGeometry.read(geometryCapture(),dom(),7,19),id,type,label,texts,derived);}
        catch(InvocationTargetException failure){Throwable cause=failure.getCause();if(cause instanceof Exception)throw (Exception)cause;throw failure;}
    }
    private static PhoneObservation.Node match(PhoneObservation f)throws Exception{
        return match(f,"depport","android.view.View","出发城市",Collections.singletonList("出发城市"),true);
    }

    private static JSONObject binding()throws Exception{
        // Synthetic PM/VD values only. The actual production OWNER compiler and
        // current Binding factory derive every v3 purpose/auth field.
        String owner="网页查询测试：在南航官方网站查询2026年11月13日北京到上海的单程航班，1名成人。"+WebFlightGoal.BACKGROUND_TAIL;
        WebFlightGoal goal=WebFlightGoal.parse(owner);
        JSONObject bg=new JSONObject().put("generation",GENERATION).put("display_id",7)
                .put("display_name","hepta-bg-"+GENERATION).put("boot_count",1)
                .put("created_elapsed_ms",500).put("expires_elapsed_ms",10000)
                .put("selected_packages",new JSONArray().put(PACKAGE));
        return WebEvidenceBinding.fromAttach(new JSONObject().put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("owner",owner).put("owner_sha256",goal.ownerSha256).put("contract_sha256",goal.contractSha256)
                .put("authorization",new JSONObject(TaskAuthorization.parse(owner).evidence())).put("background",bg)
                .put("controller_identity",new JSONObject().put("uid",10481))
                .put("helper_identity",new JSONObject().put("uid",10484).put("version_code",WebEvidenceProtocol.HELPER_VERSION_CODE)));
    }
    private static JSONObject request()throws Exception{
        return new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CAPTURE))
                .put("task_id",TASK).put("controller_session_nonce",SESSION).put("request_nonce",NONCE)
                .put("deadline_elapsed_ms",2000).put("expected_webview_instance",INSTANCE).put("expected_navigation_epoch",7);
    }
    private static JSONObject callback(JSONObject binding)throws Exception{
        return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method","captureEvidence")
                .put("request_nonce",NONCE).put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("status","unavailable").put("reason","main_frame_loading").put("actual_helper_uid",10484)
                .put("actual_display_id",7).put("actual_window_id",19).put("webview_instance",INSTANCE)
                .put("navigation_epoch",7).put("binding_sha256",WebEvidenceBinding.sha256(binding))
                .put("raw_length",0).put("raw_sha256",JSONObject.NULL).put("retired",false)
                .put("cleanup",JSONObject.NULL).put("recovery",JSONObject.NULL);
    }
    private static WebEvidenceReceipt unavailable(JSONObject cb)throws Exception{
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,request().toString(),binding(),cb.toString(),null,10484,1000,1500);
    }
    private static void badCallback(String name,Change change)throws Exception{
        test(name,()->{JSONObject c=callback(binding());change.change(c);rejects(()->unavailable(c));});
    }


    // Reuse the helper's exact pure fixture. Its OWNER/identity is explicitly
    // synthetic and is never passed to an Android task or used to grant tools.
    private static JSONObject unstartedFixture(boolean confirm)throws Exception{
        Class<?> type=Class.forName("org.trillionnium.hepta.webprotocol.WebUnstartedRetirementHostTest");
        Method initial=type.getDeclaredMethod("initial",int.class);initial.setAccessible(true);
        JSONObject first=(JSONObject)initial.invoke(null,WebEvidenceProtocol.HELPER_VERSION_CODE);
        if(!confirm)return first;
        Method next=type.getDeclaredMethod("confirmation",JSONObject.class);next.setAccessible(true);
        return (JSONObject)next.invoke(null,first);
    }
    private static JSONObject retirementInitial(JSONObject raw)throws Exception{
        return WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(raw.getString("schema"))?raw:new JSONObject(raw.getString("initial_record_utf8"));
    }
    private static JSONObject retirementCallback(JSONObject raw)throws Exception{
        JSONObject initial=retirementInitial(raw),request=new JSONObject(raw.getString("request_json_utf8"));
        byte[] bytes=(raw.toString()+"\n").getBytes(StandardCharsets.UTF_8);
        return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method","closeLease")
                .put("request_nonce",request.get("request_nonce")).put("task_id",request.get("task_id"))
                .put("controller_session_nonce",request.get("controller_session_nonce")).put("status","unstarted_retired")
                .put("reason","matching_attachment_never_started_owned_web_resources").put("actual_helper_uid",10484)
                .put("actual_display_id",-1).put("actual_window_id",-1).put("webview_instance",JSONObject.NULL)
                .put("navigation_epoch",JSONObject.NULL).put("binding_sha256",raw.get("binding_sha256"))
                .put("raw_length",bytes.length).put("raw_sha256",WebEvidenceJson.sha(bytes)).put("retired",true)
                .put("cleanup",copy(initial.getJSONObject("original_cleanup")))
                .put("recovery",WebRecoveryPolicy.evaluateUnstartedRecord(raw));
    }
    private static WebEvidenceReceipt retirement(JSONObject raw,JSONObject cb)throws Exception{
        JSONObject first=retirementInitial(raw);boolean initial=WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(raw.getString("schema"));
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CLOSE,raw.getString("request_json_utf8"),first.getJSONObject("binding"),
                cb.toString(),(raw.toString()+"\n").getBytes(StandardCharsets.UTF_8),10484,initial?3900:5900,initial?4100:6100);
    }
    private static JSONObject captureBinding()throws Exception{
        JSONObject b=binding();b.put("storage_profile_name",WebStorageEvidence.profileFor(SESSION));
        b.put("controller_identity",new JSONObject().put("uid",10481));
        b.getJSONObject("background").put("created_elapsed_ms",500).put("expires_elapsed_ms",10000);
        return b;
    }
    private static JSONObject storage()throws Exception{
        return new JSONObject().put("schema",WebStorageEvidence.ISOLATION_SCHEMA).put("library",WebStorageEvidence.LIBRARY)
                .put("runtime_multi_profile",true).put("runtime_delete_browsing_data",true)
                .put("profile_name",WebStorageEvidence.profileFor(SESSION)).put("profile_names_before",new JSONArray().put("Default"))
                .put("profile_was_present_before",false).put("profile_assigned_elapsed_ms",600)
                .put("webview_provider_package","synthetic.webview").put("webview_provider_version","unit").put("webview_provider_version_code",1)
                .put("preload_clear",new JSONObject().put("started_elapsed_ms",610).put("deadline_elapsed_ms",900)
                        .put("initial_url",JSONObject.NULL).put("callback_elapsed_ms",620).put("callback_observed",true)
                        .put("deadline_met",true).put("cookies_present_after",false).put("api","WebStorageCompat.deleteBrowsingData"))
                .put("first_load_dispatch_begin_elapsed_ms",630).put("retirement_clear",JSONObject.NULL)
                .put("all_os_sockets_observed_closed",false).put("whole_device_storage_erased",false).put("business_verified",false)
                .put("first_url",WebEvidenceProtocol.INITIAL_URL);
    }
    private static JSONObject captured()throws Exception{
        JSONObject d=dom().put("href","https://m.csair.com/").put("origin","https://m.csair.com")
                .put("ready_state","complete").put("truncated",false);
        String domRaw=d.toString();JSONObject b=captureBinding(),c=geometryCapture();
        c.put("schema",WebObservedNavigation.CAPTURE_SCHEMA).put("challenge",NONCE).put("binding",copy(b))
                .put("helper_package",PACKAGE).put("helper_uid",10484).put("helper_pid",123)
                .put("webview_instance",INSTANCE).put("navigation_epoch",7).put("committed_main_frame_url","https://m.csair.com/")
                .put("commit_elapsed_ms",950).put("current_native_url","https://m.csair.com/")
                .put("native_url_source","android.webkit.WebView.getUrl").put("commit_source","android.webkit.WebViewClient.onPageCommitVisible")
                .put("visual_request_id",5).put("dom_raw_utf8",domRaw).put("dom_sha256",WebEvidenceJson.sha(domRaw))
                .put("observer_script_sha256",WebEvidenceReceipt.OBSERVER_SHA)
                .put("business_verified",false).put("pixel_equality_claimed",false)
                .put("all_visible_semantics_verified",false).put("truncated",false);
        wireFixtureStability(c,d,b);
        return new JSONObject().put("schema",WebEvidenceProtocol.RAW_SCHEMA).put("request_json_utf8",request().toString())
                .put("request_sha256",WebEvidenceJson.sha(request().toString())).put("binding",b)
                .put("binding_sha256",WebEvidenceBinding.sha256(b)).put("controller_identity",copy(b.getJSONObject("controller_identity")))
                .put("helper_identity",copy(b.getJSONObject("helper_identity"))).put("actual_window_id",19).put("capture",c)
                .put("storage_isolation",storage()).put("actor","controller_evidence_capture")
                .put("diagnostic_unbound",false).put("business_verified",false);
    }
    private static WebEvidenceReceipt capturedReceipt(JSONObject raw)throws Exception{
        byte[] bytes=(raw.toString()+"\n").getBytes(StandardCharsets.UTF_8);
        JSONObject cb=callback(captureBinding()).put("status","captured").put("raw_length",bytes.length).put("raw_sha256",WebEvidenceJson.sha(bytes));
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,request().toString(),captureBinding(),cb.toString(),bytes,10484,1000,1500);
    }
    private static void badCapture(String name,Change change)throws Exception{
        test(name,()->{JSONObject raw=captured();change.change(raw);rejects(()->capturedReceipt(raw));});
    }

    public static void main(String[] args)throws Exception{
        check(args.length==1,"one create-only report path");
        test("native_bracket_is_a_guard_not_a_css_mapping",()->{
            WebNativeGeometry g=WebNativeGeometry.read(geometryCapture(),dom(),7,19);
            check(g!=null&&g.contains(200,600,550,800)&&!g.contains(200,100,550,200),"native rectangle only");
            check(!g.evidence().getBoolean("css_to_screen_mapping_used")&&!g.evidence().getBoolean("proves_action_or_occlusion"),"scope");
        });
        test("root_view_visible_rect_has_a_different_origin",()->{
            JSONObject c=geometryCapture();for(int i=0;i<4;i++)state(c,i).put("global_visible_rect_pixels",new JSONArray(new int[]{13,70,1213,2470}));
            check(WebNativeGeometry.read(c,dom(),7,19)!=null,"dimensions, not a guessed origin translation");
        });
        test("missing_legacy_geometry_mints_nothing",()->{JSONObject c=geometryCapture();c.remove("capture_geometry");check(WebNativeGeometry.read(c,dom(),7,19)==null,"legacy no target");});
        badGeometry("sample_wrong_display",c->state(c,2).put("display_id",8));
        badGeometry("sample_wrong_window",c->state(c,2).put("actual_window_id",20));
        badGeometry("moved_native_bounds",c->state(c,2).put("bounds_screen_pixels",new JSONArray(new int[]{1,400,1201,2800})));
        badGeometry("partly_clipped_webview",c->state(c,0).put("global_visible_rect_pixels",new JSONArray(new int[]{0,250,1199,2650})));
        badGeometry("missing_visible_rect",c->state(c,0).put("global_visible_rect_pixels",JSONObject.NULL));
        badGeometry("changed_scale",c->state(c,3).put("webview_get_scale",3.0));
        badGeometry("changed_scale_callback_sequence",c->state(c,3).put("scale_change_sequence",2));
        badGeometry("future_scale_callback",c->state(c,0).put("scale_changed_elapsed_ms",1009));
        badGeometry("unpaired_scale_callback",c->state(c,0).put("scale_callback_new",JSONObject.NULL));
        badGeometry("native_transform_not_identity",c->state(c,0).put("view_transform",new JSONArray(new int[]{1,1,0,1,0})));
        badGeometry("native_padding_unknown",c->state(c,0).put("padding_pixels",new JSONArray(new int[]{0,1,0,0})));
        badGeometry("sample_before_capture",c->state(c,0).put("sampled_elapsed_ms",999));
        badGeometry("sample_time_reversed",c->state(c,2).put("sampled_elapsed_ms",1001));
        badGeometry("phase_order_changed",c->c.getJSONObject("capture_geometry").getJSONArray("samples").getJSONObject(2).put("phase","before_js1"));
        badGeometry("capture_claims_css_mapping",c->c.getJSONObject("capture_geometry").put("css_to_screen_mapping_verified",true));
        badGeometry("viewport_mode_disabled",c->state(c,0).put("load_with_overview_mode",false));
        badGeometry("extra_native_field",c->state(c,0).put("caller_coordinate_authority",true));
        test("unknown_visual_viewport_rejected",()->{JSONObject d=dom();d.put("visual_viewport",JSONObject.NULL);rejects(()->WebNativeGeometry.read(geometryCapture(),d,7,19));});
        test("geometry_cross_capture_change_rejected",()->{
            WebNativeGeometry a=WebNativeGeometry.read(geometryCapture(),dom(),7,19);JSONObject c=geometryCapture();
            for(int i=0;i<4;i++)state(c,i).put("scroll_pixels",new JSONArray(new int[]{0,1}));
            check(!a.same(WebNativeGeometry.read(c,dom(),7,19)),"scroll change matters without CSS conversion");
        });
        test("capture_decimals_do_not_relax_request_or_retirement_json",()->{
            String raw=geometryCapture().toString();check(WebEvidenceJson.parseCaptureEvidence(raw,65536)!=null,"capture finite decimals");
            rejects(()->WebEvidenceJson.parseEvidence(raw,65536));rejects(()->WebEvidenceJson.parse("{\"uid\":10484.5}",1024));
            JSONObject fake=new JSONObject().put("uid",10484.5);rejects(()->WebEvidenceJson.integer(fake,"uid"));
        });

        test("real_child_collector_dedup_is_not_full_value_proof",()->{
            ObservedChildText.Result label=child("出发城市","出发城市");
            check("derived".equals(label.status)&&!label.sourcesComplete&&!label.truncated,"actual dedup shape");
            PhoneObservation.Node n=field("n1","depport",label);check(match(frame(n))==n,"same semantic native node");
        });
        test("one_native_exact_own_label",()->{
            PhoneObservation.Node n=node("n1","depport",PACKAGE,"android.view.View","出发城市",new Rect(200,600,550,800),
                    true,true,false,false,false,ObservedChildText.notApplicable(),null);
            check(match(frame(n))==n,"exact own label");
        });
        test("homepage_uses_actual_native_button_label",()->{
            String label="机票预订按钮，点按两次即可激活";
            PhoneObservation.Node n=node("n2","",PACKAGE,"android.widget.Button",label,new Rect(200,600,550,800),
                    true,true,false,false,false,ObservedChildText.notApplicable(),null);
            check(match(frame(n),"","android.widget.Button",label,Collections.singletonList(label),false)==n,"homepage AX button");
        });
        test("duplicate_native_id_not_filtered_to_unique",()->{
            PhoneObservation.Node a=field("n1","depport",child("出发城市"));
            PhoneObservation.Node b=node("n2","depport",PACKAGE,"android.view.View","出发城市",new Rect(600,600,900,800),
                    true,false,false,false,false,ObservedChildText.notApplicable(),null);
            check(match(frame(a,b))==null,"disabled duplicate still ambiguous");
        });
        test("native_header_cannot_supply_web_field",()->{
            PhoneObservation.Node n=node("n1","depport",PACKAGE,"android.view.View","出发城市",new Rect(200,100,550,200),
                    true,true,false,false,false,ObservedChildText.notApplicable(),null);
            check(match(frame(n))==null,"outside actual WebView");
        });
        test("native_zero_bounds_rejected",()->{
            PhoneObservation.Node n=node("n1","depport",PACKAGE,"android.view.View","出发城市",new Rect(0,0,0,0),
                    true,true,false,false,false,ObservedChildText.notApplicable(),null);check(match(frame(n))==null,"offscreen AX");
        });
        test("native_root_clip_rejected",()->{
            PhoneObservation.Node n=field("n1","depport",child("出发城市"));
            check(match(frame(Collections.singletonList(n),new int[]{0,0,500,2800},new int[]{0,0,1200,2800}))==null,"root rectangle");
        });
        test("native_window_clip_rejected",()->{
            PhoneObservation.Node n=field("n1","depport",child("出发城市"));
            check(match(frame(Collections.singletonList(n),new int[]{0,0,1200,2800},new int[]{0,0,500,2800}))==null,"window rectangle");
        });
        for(int bad=0;bad<6;bad++){final int flag=bad;test("native_state_negative_"+bad,()->{
            PhoneObservation.Node n=node("n1","depport",flag==0?"other.package":PACKAGE,
                    flag==1?"android.widget.Button":"android.view.View","出发城市",new Rect(200,600,550,800),
                    flag!=2,flag!=3,flag==4,flag==5,false,ObservedChildText.notApplicable(),null);
            check(match(frame(n))==null,"actual native state");
        });}
        test("other_label_cannot_borrow_child_label",()->{
            PhoneObservation.Node n=node("n1","depport",PACKAGE,"android.view.View","付款",new Rect(200,600,550,800),
                    true,true,false,false,false,child("出发城市"),null);check(match(frame(n))==null,"own label precedence");
        });
        test("unreviewed_child_semantics_rejected",()->check(match(frame(field("n1","depport",child("出发城市","购买"))))==null,"child source hash"));
        test("partial_child_label_rejected",()->check(match(frame(field("n1","depport",child("出发"))))==null,"not substring"));
        test("resource_suffix_is_not_an_id_match",()->check(match(frame(field("n1","foreign:depport",child("出发城市"))))==null,"exact ID"));
        test("stale_child_root_signature_rejected",()->{
            PhoneObservation.Node n=node("n1","depport",PACKAGE,"android.view.View","",new Rect(200,600,550,800),
                    true,true,false,false,false,child("出发城市"),repeat("f",64));check(match(frame(n))==null,"actual root signature");
        });
        test("truncated_child_provenance_rejected",()->check(match(frame(field("n1","depport",child("出发城市",repeat("长",120)))))==null,"complete retained text"));

        test("authenticated_unavailable_keeps_only_metadata",()->{
            WebEvidenceReceipt r=unavailable(callback(binding()));
            check("unavailable".equals(r.status)&&r.capture()==null&&r.dom()==null&&!r.cleanupKnown&&!r.recovered,"no proof promotion");
        });
        badCallback("unavailable_wrong_binding",c->c.put("binding_sha256",repeat("e",64)));
        badCallback("unavailable_wrong_uid",c->c.put("actual_helper_uid",10485));
        badCallback("unavailable_wrong_display",c->c.put("actual_display_id",0));
        badCallback("unavailable_missing_window",c->c.put("actual_window_id",-1));
        badCallback("unavailable_wrong_instance",c->c.put("webview_instance",GENERATION));
        badCallback("unavailable_wrong_epoch",c->c.put("navigation_epoch",8));
        badCallback("unavailable_retired",c->c.put("retired",true));
        badCallback("unavailable_cleanup_claim",c->c.put("cleanup",new JSONObject()));
        badCallback("unavailable_recovery_claim",c->c.put("recovery",new JSONObject()));
        badCallback("unavailable_wrong_nonce",c->c.put("request_nonce",repeat("6",64)));
        badCallback("unavailable_wrong_task",c->c.put("task_id",repeat("7",32)));
        badCallback("unavailable_wrong_session",c->c.put("controller_session_nonce",repeat("8",64)));
        badCallback("unavailable_unknown_callback_key",c->c.put("allowed_click",true));
        badCallback("rejected_is_not_wait",c->c.put("status","rejected"));
        badCallback("captured_without_fd_is_not_wait",c->c.put("status","captured"));
        test("unavailable_with_fd_rejected",()->{
            byte[] raw="{}".getBytes(StandardCharsets.UTF_8);JSONObject c=callback(binding());
            c.put("raw_length",raw.length).put("raw_sha256",WebEvidenceJson.sha(raw));
            rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,request().toString(),binding(),c.toString(),raw,10484,1000,1500));
        });
        test("unavailable_after_deadline_rejected",()->{
            JSONObject c=callback(binding());rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,request().toString(),binding(),c.toString(),null,10484,1000,2001));
        });
        test("unavailable_close_never_retires",()->{
            JSONObject q=new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CLOSE)).put("request_nonce",NONCE)
                    .put("task_id",TASK).put("controller_session_nonce",SESSION).put("deadline_elapsed_ms",2000).put("reason","normal");
            JSONObject c=callback(binding()).put("method","closeLease");
            rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CLOSE,q.toString(),binding(),c.toString(),null,10484,1000,1500));
        });
        test("wait_domain_keeps_owner_and_cannot_click_or_succeed",()->{
            String owner="网页查询测试：在南航官方网站查询2026年11月13日北京到上海的单程航班，1名成人。"+WebFlightGoal.BACKGROUND_TAIL;
            WebFlightGoal goal=WebFlightGoal.parse(owner);TaskAuthorization.Gate auth=TaskAuthorization.parse(owner).bind(TASK);
            check(goal!=null&&auth.authorization.allowedTools.equals(WebEvidenceProtocol.READ_ONLY_TOOLS),"actual original OWNER compiler");
            WebEvidenceReceipt r=unavailable(callback(binding()));
            WebFlightDomain d=WebFlightDomain.waiting(TASK,goal,auth,frame(),r,WebEvidenceBinding.sha256(binding()));
            check(d.clickIds.isEmpty()&&d.editValues.isEmpty()
                    &&d.toolMask(auth.authorization.allowedTools).equals(new java.util.HashSet<String>(Arrays.asList("wait","done"))),"no effect tools");
            d.requireCurrent(ActionDecision.parse("{\"action\":\"wait\",\"observation_id\":\""+OBS+"\",\"package\":\""+PACKAGE+"\",\"duration_ms\":100}"));
            rejects(()->d.requireCurrent(ActionDecision.parse("{\"action\":\"done\",\"observation_id\":\""+OBS+"\",\"package\":\""+PACKAGE+"\",\"status\":\"success\",\"summary\":\"done\"}")));
            rejects(()->d.requireCurrent(ActionDecision.parse("{\"action\":\"click\",\"observation_id\":\""+OBS+"\",\"package\":\""+PACKAGE+"\",\"node_label\":\"出发城市\",\"node_id\":\"n1\"}")));
            check(Boolean.FALSE.equals(d.evidence().get("cleanup_known"))&&Boolean.FALSE.equals(d.evidence().get("business_verified")),"pending remains pending");
        });

        test("code4_capture_crosses_real_receipt_geometry_storage_parsers",()->{
            WebEvidenceReceipt r=capturedReceipt(captured());
            check(r.capture()!=null&&r.dom()!=null&&!r.cleanupKnown&&!r.recovered&&!r.unstarted,"capture is not completion");
            check(WebNativeGeometry.read(r.capture(),r.dom(),7,19)!=null,"actual parser consumes finite native scale samples");
        });
        badCapture("captured_missing_new_geometry",r->r.getJSONObject("capture").remove("capture_geometry"));
        badCapture("captured_legacy_observer_script",r->r.getJSONObject("capture").put("observer_script_sha256","763da807f3225fc0e2ed22253caf00c6787cb7557fa23407ab9d5b3547700c2a"));
        badCapture("captured_geometry_window_changed",r->state(r.getJSONObject("capture"),2).put("actual_window_id",20));
        badCapture("capture_callback_storage_not_completed",r->r.getJSONObject("storage_isolation").getJSONObject("preload_clear").put("callback_observed",false));
        badCapture("capture_diagnostic_not_task_evidence",r->r.put("diagnostic_unbound",true));
        badCapture("capture_request_raw_changed",r->r.put("request_json_utf8",r.getString("request_json_utf8")+" "));
        badCapture("capture_decimal_identity_refused",r->r.getJSONObject("capture").put("helper_uid",10484.5));
        badCapture("capture_business_scope_not_promoted",r->r.getJSONObject("capture").put("business_verified",true));
        test("unstarted_initial_fd_replayed_without_upgrading_cleanup",()->{
            JSONObject raw=unstartedFixture(false);WebEvidenceReceipt r=retirement(raw,retirementCallback(raw));
            check(r.cleanupKnown&&r.unstarted&&!r.recovered,"distinct never-started retirement");
            check(!r.callback().getJSONObject("cleanup").getBoolean("webview_destroyed")
                    &&!r.callback().getJSONObject("cleanup").getBoolean("storage_clear_completed"),"original nonperformed cleanup stays false");
        });
        test("unstarted_confirmation_binds_original_and_fresh_close",()->{
            JSONObject raw=unstartedFixture(true);WebEvidenceReceipt r=retirement(raw,retirementCallback(raw));
            check(r.cleanupKnown&&r.unstarted&&!r.recovered,"new process confirmation preserves initial original");
        });
        test("unstarted_callback_cannot_upgrade_cleanup",()->{
            JSONObject raw=unstartedFixture(false),cb=retirementCallback(raw);cb.getJSONObject("cleanup").put("webview_destroyed",true);
            rejects(()->retirement(raw,cb));
        });
        test("unstarted_reply_cannot_claim_live_window",()->{
            JSONObject raw=unstartedFixture(false),cb=retirementCallback(raw);cb.put("actual_window_id",37).put("actual_display_id",15);
            rejects(()->retirement(raw,cb));
        });
        test("unstarted_original_resource_creation_refused",()->{
            JSONObject raw=unstartedFixture(false);raw.getJSONObject("resource_fence_before").put("resource_creation_dispatched",true);
            rejects(()->retirement(raw,retirementCallback(raw)));
        });
        test("unstarted_confirmation_embedded_hash_refused",()->{
            JSONObject raw=unstartedFixture(true);raw.put("initial_record_sha256",repeat("0",64));
            rejects(()->retirement(raw,retirementCallback(raw)));
        });
        test("unstarted_missing_fd_never_releases_marker",()->{
            JSONObject raw=unstartedFixture(false),cb=retirementCallback(raw);cb.put("raw_length",0).put("raw_sha256",JSONObject.NULL);
            rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CLOSE,raw.getString("request_json_utf8"),
                    raw.getJSONObject("binding"),cb.toString(),null,10484,3900,4100));
        });
        test("observer_code2_cannot_be_formal_capture_peer",()->{
            JSONObject b=binding();b.getJSONObject("helper_identity").put("version_code",2);
            JSONObject cb=callback(b);rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,request().toString(),b,cb.toString(),null,10484,1000,1500));
        });

        JSONObject out=new JSONObject().put("schema","hepta.web-flight-evidence-host-cases.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("production_pure_classes_executed",true).put("android_rect_and_ax_fixture",true)
                .put("binder_transport_authenticated",false).put("native_geometry_is_synthetic",true)
                .put("phone_commands_executed",0).put("query_executed",false).put("business_verified",false);
        Path output=Paths.get(args[0]);Files.write(output,(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("WebFlightEvidenceHostTest cases="+names.size()+" assertions="+assertions);
    }
}
