package org.trillionnium.hepta.local;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.*;

/** Synthetic complete DOM/native pairs; exercises the merged production pure admission rules. */
public final class FlightObservationBracketHost {
    static final String TASK="11111111111111111111111111111111",TARGET="0/0/1/0";
    static int cases,assertions;static final JSONArray names=new JSONArray();
    interface Work {void run()throws Exception;}
    static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void test(String name,Work work)throws Exception{work.run();cases++;names.put(name);}
    static void denied(Work work)throws Exception{boolean no=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException|JSONException expected){no=true;}check(no,"invalid bracket accepted");}
    static Object factory(Class<?> cls,String name,Class<?>[] types,Object... args)throws Exception{
        Method m=cls.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;}
    }
    static JSONObject old(String name)throws Exception{return (JSONObject)factory(WebFlightEvidenceHostTest.class,name,new Class<?>[0]);}
    static JSONObject policyDom()throws Exception{return (JSONObject)factory(WebFlightNativeStabilityHostTest.class,"dom",new Class<?>[0]);}
    static JSONArray nativeTree(int ad)throws Exception{return (JSONArray)factory(WebFlightNativeStabilityHostTest.class,"nativeTree",new Class<?>[]{int.class,int.class},ad,100);}
    static JSONArray retained()throws Exception{
        JSONArray all=(JSONArray)factory(WebFlightNativeStabilityHostTest.class,"retained",new Class<?>[0]);
        return new JSONArray().put(all.getJSONObject(0)).put(all.getJSONObject(1));
    }
    static JSONObject dom()throws Exception{
        JSONObject d=old("dom"),policy=policyDom();d.put("schema",WebDomStability.DOM_SCHEMA).put("href","https://m.csair.com/")
                .put("ready_state","complete").put("truncated",false).put("truncation_reasons",new JSONArray());
        JSONArray nodes=policy.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);
            for(String k:new String[]{"name","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed","item_type","item_prop"})n.put(k,"");
            for(String k:new String[]{"disabled","item_scope","iframe_contents_read"})n.put(k,false);
            n.put("value",JSONObject.NULL).put("aria_disabled",JSONObject.NULL);
        }
        return d.put("nodes",nodes).put("visited",nodes.length());
    }
    static JSONObject capture(JSONObject binding,JSONObject dom,int start)throws Exception{
        JSONObject c=old("geometryCapture");String raw=WebDomCanonical.canonical(dom);
        WebDomStability.Result stable=WebDomStability.evaluate(raw,raw,WebTaskPurpose.FLIGHT_POLICY_ID);
        JSONObject proof=stable.evidence();String proofSha=WebDomCanonical.sha256(proof);
        c.put("binding",binding).put("display_id",7).put("actual_window_id",71)
                .put("started_elapsed_ms",start).put("ended_elapsed_ms",start+10)
                .put("committed_main_frame_url","https://m.csair.com/").put("current_native_url","https://m.csair.com/")
                .put("helper_package",WebEvidenceProtocol.HELPER_PACKAGE).put("helper_uid",10484).put("helper_pid",42)
                .put("observed_link_navigation",JSONObject.NULL).put("truncated",false)
                .put("webview_instance","12345678-1234-1234-1234-123456789012").put("navigation_epoch",1)
                .put("commit_elapsed_ms",900).put("observer_script_sha256","synthetic-fixed-observer")
                .put("challenge","synthetic-capture-"+start).put("before_dom_raw_utf8",raw).put("dom_raw_utf8",raw)
                .put("before_dom_sha256",stable.beforeRawSha256).put("dom_sha256",stable.afterRawSha256)
                .put("dom_stability",proof).put("dom_stability_sha256",proofSha).put("comparison_scope",stable.comparisonScope)
                .put("raw_dom_equal",stable.rawEqual).put("webview_bounds_screen_pixels",new JSONArray(new int[]{0,0,400,700}));
        JSONObject geometry=c.getJSONObject("capture_geometry");geometry.put("dom_comparison_scope",stable.comparisonScope)
                .put("dom_stability_sha256",proofSha);
        JSONArray samples=geometry.getJSONArray("samples");
        for(int i=0;i<4;i++)samples.getJSONObject(i).getJSONObject("native")
                .put("sampled_elapsed_ms",start+1+i).put("actual_window_id",71)
                .put("bounds_screen_pixels",new JSONArray(new int[]{0,0,400,700}))
                .put("global_visible_rect_pixels",new JSONArray(new int[]{0,0,400,700}));
        return c;
    }
    static JSONObject frame(JSONObject binding,JSONArray nativeRows,String id)throws Exception{
        JSONObject bg=binding.getJSONObject("background");JSONArray nodes=retained();
        return new JSONObject().put("observation_id",id).put("package",WebEvidenceProtocol.HELPER_PACKAGE)
                .put("window_id",71).put("nodes_truncated",false).put("ime_visible",false).put("nodes",nodes)
                .put("screen_sha256",id).put("app_tree_sha256",id).put("observation_state_sha256",id)
                .put("window",new JSONObject().put("metadata_status","observed").put("window_id",71).put("display_id",7).put("type",1)
                        .put("root_class_truncated",false).put("title_truncated",false).put("root_class","android.widget.FrameLayout")
                        .put("root_bounds",new JSONArray(new int[]{0,0,400,700})))
                .put("background_session",new JSONObject().put("mode","background").put("display_id",7).put("generation",bg.get("generation"))
                        .put("bootstrap_package",WebEvidenceProtocol.HELPER_PACKAGE).put("allowed_packages",bg.getJSONArray("selected_packages")))
                .put("collection",new JSONObject().put("schema","hepta.observation-collection.v1").put("source","same_observed_accessibility_traversal")
                        .put("visited_nodes",nativeRows.length()).put("retained_nodes",nodes.length()).put("truncation_reasons",new JSONArray())
                        .put("pending_nodes_at_stop",0).put("child_slots_omitted_by_traversal_limit",0)
                        .put("nodes_omitted_by_node_limit",0).put("nodes_omitted_by_text_limit",0).put("elapsed_ms",4));
    }
    static final class Pair {
        JSONObject binding,first,last,before,after;JSONArray nativeBefore,nativeAfter;
        Pair()throws Exception{
            binding=old("binding");JSONObject d=dom();first=capture(binding,d,1000);last=capture(binding,d,1100);
            nativeBefore=nativeTree(0);nativeAfter=nativeTree(1);before=frame(binding,nativeBefore,"before");after=frame(binding,nativeAfter,"after");
        }
        JSONObject verify()throws Exception{return WebFlightNativeStability.compareObservationBracket(TASK,before,nativeBefore,after,nativeAfter,first,last,TARGET);}
    }
    static JSONObject shiftedDom()throws Exception{
        JSONObject d=dom();JSONArray nodes=d.getJSONArray("nodes");String slider=null;
        for(int i=0;i<nodes.length();i++)if("slider4".equals(nodes.getJSONObject(i).optString("id")))slider=nodes.getJSONObject(i).getString("path");
        check(slider!=null,"fixture slider");
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);String path=n.getString("path");
            if(path.equals(slider)||path.startsWith(slider+"/")){
                JSONArray rect=n.getJSONArray("rect_css_pixels");rect.put(0,rect.getDouble(0)-20).put(2,rect.getDouble(2)-20);
            }
        }
        return d;
    }
    public static void main(String[] args)throws Exception{
        test("carousel_native_change_admits_read_only_bracket_without_action",()->{
            JSONObject result=new Pair().verify();check("readonly_current_page_observation".equals(result.getString("purpose")),"wrong purpose");
            check(!result.getBoolean("action_permit_created")&&!result.getBoolean("business_verified")&&!result.getBoolean("coordinates_used_for_input"),"read-only proof granted action or business success");
        });
        test("each_capture_original_dom_pair_must_match",()->{Pair p=new Pair();p.last.put("before_dom_raw_utf8",p.last.getString("before_dom_raw_utf8")+" ");denied(p::verify);});
        test("strict_carousel_dom_translation_admits_read_only_with_native_proof",()->{
            Pair p=new Pair();p.last=capture(p.binding,shiftedDom(),1100);JSONObject proof=p.verify();
            check(!proof.getBoolean("all_four_dom_raws_equal")&&proof.getBoolean("each_capture_full_raw_dom_stable"),"equal raw incorrectly claimed");
            check(proof.getJSONObject("dom").getDouble("horizontal_translation_css_pixels")==-20,"translation missing");
            check(!proof.getBoolean("action_permit_created")&&!proof.getBoolean("business_verified"),"scope grants action");
            check(!proof.getString("first_dom_sha256").equals(proof.getString("last_dom_sha256")),"original two hashes omitted");
        });
        test("cross_capture_booking_form_value_change_rejected",()->{
            Pair p=new Pair();JSONObject d=shiftedDom();JSONArray nodes=d.getJSONArray("nodes");
            for(int i=0;i<nodes.length();i++)if("booking".equals(nodes.getJSONObject(i).optString("id")))nodes.getJSONObject(i).put("value","changed-route");
            p.last=capture(p.binding,d,1100);denied(p::verify);
        });
        test("cross_capture_carousel_semantic_change_rejected",()->{
            Pair p=new Pair();JSONObject d=shiftedDom();JSONArray nodes=d.getJSONArray("nodes");
            for(int i=0;i<nodes.length();i++)if("advertising0".equals(nodes.getJSONObject(i).optString("id")))nodes.getJSONObject(i).put("text","price changed");
            p.last=capture(p.binding,d,1100);denied(p::verify);
        });
        test("foreign_task_rejected",()->{Pair p=new Pair();denied(()->WebFlightNativeStability.compareObservationBracket("other",p.before,p.nativeBefore,p.after,p.nativeAfter,p.first,p.last,TARGET));});
        test("new_generation_capture_rejected",()->{Pair p=new Pair();JSONObject b=new JSONObject(p.last.getJSONObject("binding").toString());b.getJSONObject("background").put("generation","other");p.last.put("binding",b);denied(p::verify);});
        test("new_instance_rejected",()->{Pair p=new Pair();p.last.put("webview_instance","different");denied(p::verify);});
        test("new_navigation_epoch_rejected",()->{Pair p=new Pair();p.last.put("navigation_epoch",2);denied(p::verify);});
        test("overlapping_capture_intervals_rejected",()->{Pair p=new Pair();p.last.put("started_elapsed_ms",1009);denied(p::verify);});
        test("different_native_window_rejected",()->{Pair p=new Pair();p.after.getJSONObject("window").put("window_id",72);denied(p::verify);});
        test("incomplete_native_traversal_count_rejected",()->{Pair p=new Pair();p.after.getJSONObject("collection").put("visited_nodes",22);denied(p::verify);});
        test("omitted_child_slots_rejected",()->{Pair p=new Pair();p.after.getJSONObject("collection").put("child_slots_omitted_by_traversal_limit",1);denied(p::verify);});
        test("truncated_rows_rejected",()->{Pair p=new Pair();p.after.put("nodes_truncated",true);denied(p::verify);});
        test("visible_ime_rejected",()->{Pair p=new Pair();p.after.put("ime_visible",true);denied(p::verify);});
        test("non_homepage_capture_rejected",()->{Pair p=new Pair();p.last.put("current_native_url","https://m.csair.com/booking_new/");denied(p::verify);});
        test("changed_booking_target_label_rejected",()->{Pair p=new Pair();p.nativeAfter.getJSONObject(p.nativeAfter.length()-1).put("text","支付");denied(p::verify);});
        test("foreign_native_package_rejected",()->{Pair p=new Pair();p.nativeAfter.getJSONObject(4).put("package","other.app");denied(p::verify);});
        test("changed_non_carousel_ancestor_rejected",()->{Pair p=new Pair();p.nativeAfter.getJSONObject(1).getJSONArray("bounds").put(3,699);denied(p::verify);});
        test("malformed_native_geometry_rejected",()->{Pair p=new Pair();p.last.getJSONObject("capture_geometry").getJSONArray("samples").getJSONObject(2)
                .getJSONObject("native").getJSONArray("bounds_screen_pixels").put(3,699);denied(p::verify);});
        JSONObject report=new JSONObject().put("schema","hepta.flight-observation-bracket-host.v1").put("cases",cases).put("assertions",assertions)
                .put("all_pass",true).put("case_names",names).put("synthetic_dom_native_capture_values",true).put("phone_operations",0)
                .put("service_token_or_android_dispatch_tested",false).put("business_verified",false);
        Files.write(Paths.get(args[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(report.toString());
    }
}
