package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;

/** Synthetic policy tests. No actual page, accessibility node, or phone action is supplied. */
public final class WebFlightNativeStabilityHostTest {
    private static final String LABEL=WebFlightNativeStability.LABEL;
    private static final String TARGET="0/0/1/0",SLIDER="0/0/0";
    private static final List<String> passed=new ArrayList<String>();
    private static int assertions;
    private interface Run { void run() throws Exception; }
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Run run)throws Exception{run.run();passed.add(name);}
    private static void denied(Run run)throws Exception{
        boolean refused=false;try{run.run();}catch(IllegalArgumentException expected){refused=true;}
        check(refused,"invalid evidence was accepted");
    }
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static JSONArray copy(JSONArray value){return new JSONArray(value.toString());}
    private static JSONObject at(JSONArray rows,String path)throws Exception{
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);
        throw new IllegalArgumentException("fixture path missing: "+path);
    }
    private static JSONArray without(JSONArray rows,String path)throws Exception{
        JSONArray result=new JSONArray();
        for(int i=0;i<rows.length();i++)if(!path.equals(rows.getJSONObject(i).getString("path")))result.put(rows.getJSONObject(i));
        return result;
    }
    private static JSONObject domNode(String path,String parent,String tag,String id,int x,int y,int width,int height)throws Exception{
        return new JSONObject().put("path",path).put("parent_path",parent==null?JSONObject.NULL:parent)
                .put("tag",tag).put("id",id).put("text","").put("role","").put("aria_label","")
                .put("href_raw",JSONObject.NULL).put("href_resolved",JSONObject.NULL).put("link_target",JSONObject.NULL)
                .put("hidden_attr",false).put("inert_attr",false).put("visible_in_viewport",true)
                .put("rect_css_pixels",new JSONArray(new int[]{x,y,x+width,y+height}));
    }
    private static JSONObject dom()throws Exception{
        JSONArray rows=new JSONArray().put(domNode("0",null,"main","",0,0,400,700))
                .put(domNode("0/0","0","ul","slider4",0,0,800,100));
        for(int i=0;i<8;i++){
            String path="0/0/"+i;
            rows.put(domNode(path,"0/0","li","advertising"+i,i*100,0,100,100));
            rows.put(domNode(path+"/0",path,"img","",i*100,0,100,100));
        }
        rows.put(domNode("0/1","0","div","booking",0,97,400,103));
        rows.put(domNode("0/1/0","0/1","div","",0,97,400,103)
                .put("role","button").put("aria_label",LABEL).put("text","机票预订"));
        return new JSONObject().put("href","https://m.csair.com/").put("ready_state","complete")
                .put("truncated",false).put("nodes",rows);
    }
    private static JSONObject translated(JSONObject before,int dx)throws Exception{
        JSONObject result=copy(before);JSONArray nodes=result.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){
            JSONObject node=nodes.getJSONObject(i);String path=node.getString("path");
            if(path.equals("0/0")||path.startsWith("0/0/")){
                JSONArray box=node.getJSONArray("rect_css_pixels");
                box.put(0,box.getInt(0)+dx);box.put(2,box.getInt(2)+dx);
            }
        }
        return result;
    }
    private static JSONObject nativeNode(String path,String parentClass,String clazz,String id,int children,
            boolean visible,int left,int top,int right,int bottom)throws Exception{
        return new JSONObject().put("path",path).put("parent_class",parentClass)
                .put("package",WebEvidenceProtocol.HELPER_PACKAGE).put("window_id",71)
                .put("class",clazz).put("view_id",id).put("text","").put("description","")
                .put("bounds",new JSONArray(new int[]{left,top,right,bottom})).put("visible",visible)
                .put("enabled",true).put("clickable",false).put("editable",false).put("scrollable",false)
                .put("focused",false).put("password",false).put("children",children)
                .put("scroll_actions","none").put("ime_enter","none").put("input_sha256",JSONObject.NULL);
    }
    private static JSONArray nativeTree(int visibleAd,int height)throws Exception{
        JSONArray rows=new JSONArray()
                .put(nativeNode("0","","android.widget.FrameLayout","",1,true,0,0,400,700))
                .put(nativeNode("0/0","android.widget.FrameLayout","android.webkit.WebView","",2,true,0,0,400,700))
                .put(nativeNode(SLIDER,"android.webkit.WebView","android.widget.ListView","slider4",8,true,0,0,400,height));
        for(int i=0;i<8;i++){
            String path=SLIDER+"/"+i;boolean visible=i==visibleAd;
            rows.put(nativeNode(path,"android.widget.ListView","android.view.View","advertising"+i,1,visible,0,0,visible?400:0,visible?height:0));
            rows.put(nativeNode(path+"/0","android.view.View","android.widget.Image","",0,visible,0,0,visible?400:0,visible?height:0));
        }
        rows.put(nativeNode("0/0/1","android.webkit.WebView","android.view.View","booking",1,true,0,97,400,200));
        rows.put(nativeNode(TARGET,"android.view.View","android.widget.Button","",0,true,0,97,400,200)
                .put("text",LABEL).put("clickable",true));
        return rows;
    }
    private static JSONObject retainedNode(String path,String id,String text)throws Exception{
        return new JSONObject().put("id",id).put("native_tree_position",new JSONObject().put("path",path))
                .put("text",text).put("bounds",new JSONArray(new int[]{0,97,400,200}));
    }
    private static JSONArray retained()throws Exception{
        return new JSONArray().put(retainedNode(TARGET,"n8",LABEL))
                .put(retainedNode("0/0/1","n7",""))
                .put(retainedNode(SLIDER+"/0","n3",""));
    }

    public static void main(String[] args)throws Exception{
        check(args.length==1,"one new output path required");final Path output=Paths.get(args[0]);
        check(!Files.exists(output),"create-only output required");
        test("unchanged_complete_dom_and_no_business_claim",()->{
            JSONObject a=dom(),p=WebFlightNativeStability.compareDom(a,copy(a));
            check(p.getBoolean("whole_dom_equal")&&p.getJSONArray("changes").length()==0,"unchanged DOM proof");
            check(!p.getBoolean("business_verified")&&!p.getBoolean("coordinates_used_for_input")&&!p.getBoolean("fully_unoccluded_claimed"),"policy scope only");
        });
        test("eight_image_horizontal_dom_translation",()->{
            JSONObject a=dom(),p=WebFlightNativeStability.compareDom(a,translated(a,20));
            check(!p.getBoolean("whole_dom_equal")&&p.getDouble("horizontal_translation_css_pixels")==20
                    &&p.getJSONArray("changes").length()==17,"all and only known carousel records moved");
        });
        test("booking_dom_change_rejected",()->{JSONObject a=dom(),b=translated(a,20);at(b.getJSONArray("nodes"),"0/1/0").put("text","改签");denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("non_carousel_dom_geometry_change_rejected",()->{JSONObject a=dom(),b=copy(a);at(b.getJSONArray("nodes"),"0/1").getJSONArray("rect_css_pixels").put(1,98);denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("dom_membership_removal_rejected",()->{JSONObject a=dom(),b=copy(a);b.put("nodes",without(b.getJSONArray("nodes"),"0/0/3/0"));denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("duplicate_dom_path_rejected",()->{JSONObject a=dom(),b=copy(a);b.getJSONArray("nodes").put(copy(at(b.getJSONArray("nodes"),"0/1")));denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("carousel_link_semantics_rejected_even_unchanged",()->{JSONObject a=dom();at(a.getJSONArray("nodes"),"0/0/0/0").put("href_raw","/purchase");denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("carousel_label_semantics_rejected_even_unchanged",()->{JSONObject a=dom();at(a.getJSONArray("nodes"),"0/0/0/0").put("aria_label","点击购买");denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("visible_dialog_rejected_even_unchanged",()->{JSONObject a=dom();at(a.getJSONArray("nodes"),"0").put("role","dialog");denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("visible_embedded_frame_rejected_even_unchanged",()->{JSONObject a=dom();at(a.getJSONArray("nodes"),"0").put("tag","iframe");denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("unrecognized_carousel_descendant_rejected",()->{JSONObject a=dom();a.getJSONArray("nodes").put(domNode("0/0/0/0/0","0/0/0/0","span","",0,0,1,1));denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("vertical_carousel_motion_rejected",()->{JSONObject a=dom(),b=translated(a,20);at(b.getJSONArray("nodes"),"0/0/2").getJSONArray("rect_css_pixels").put(1,1);denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("nonuniform_horizontal_motion_rejected",()->{JSONObject a=dom(),b=translated(a,20);JSONObject n=at(b.getJSONArray("nodes"),"0/0/2/0");n.getJSONArray("rect_css_pixels").put(0,221).put(2,321);denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("translation_over_observed_width_rejected",()->{JSONObject a=dom();denied(()->WebFlightNativeStability.compareDom(a,translated(a,801)));});
        test("loading_dom_rejected",()->{JSONObject a=dom();a.put("ready_state","loading");denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("truncated_dom_rejected",()->{JSONObject a=dom();a.put("truncated",true);denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("wrong_official_origin_rejected",()->{JSONObject a=dom();a.put("href","https://example.invalid/");denied(()->WebFlightNativeStability.compareDom(a,copy(a)));});
        test("native_carousel_change_keeps_three_pixel_overlap",()->{
            JSONArray a=nativeTree(0,100),b=nativeTree(1,100);JSONObject p=WebFlightNativeStability.compareNative(a,b,TARGET);
            check(p.getBoolean("existing_target_overlap_unchanged")&&p.getBoolean("observed_target_interior_clear"),"overlap and interior independently checked");
            JSONArray overlap=p.getJSONArray("existing_target_overlap");
            check(overlap.length()==1&&overlap.getJSONArray(0).getInt(1)==97&&overlap.getJSONArray(0).getInt(3)==100,"three-pixel strip retained");
            check(!p.getBoolean("ordinal_node_ids_used_for_rebinding")&&!p.getBoolean("business_verified"),"no rebinding or business proof");
        });
        test("native_target_text_change_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,TARGET).put("text","支付");denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_ancestor_bounds_change_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,"0/0").getJSONArray("bounds").put(3,699);denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_omitted_child_rejected",()->{JSONArray a=nativeTree(0,100),b=without(copy(a),SLIDER+"/4/0");denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_duplicate_path_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);b.put(copy(at(b,TARGET)));denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_foreign_package_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,SLIDER+"/2").put("package","other.app");denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_mixed_window_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,SLIDER+"/2").put("window_id",72);denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_parent_class_change_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,TARGET).put("parent_class","android.widget.Other");denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_carousel_action_state_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,SLIDER+"/0").put("focused",true);denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_visible_carousel_outside_container_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,SLIDER+"/0").getJSONArray("bounds").put(2,401);denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_target_overlap_change_rejected",()->{JSONArray a=nativeTree(0,100),b=copy(a);at(b,SLIDER+"/0").getJSONArray("bounds").put(3,98);at(b,SLIDER+"/0/0").getJSONArray("bounds").put(3,98);denied(()->WebFlightNativeStability.compareNative(a,b,TARGET));});
        test("native_target_center_covered_rejected_even_unchanged",()->{JSONArray a=nativeTree(0,160);denied(()->WebFlightNativeStability.compareNative(a,copy(a),TARGET));});
        test("native_missing_target_rejected",()->{JSONArray a=nativeTree(0,100);denied(()->WebFlightNativeStability.compareNative(a,copy(a),"0/0/1/9"));});
        test("retained_ordinal_change_is_not_node_rebinding",()->{
            JSONArray a=retained(),b=copy(a);b.getJSONObject(0).put("id","n9");
            JSONObject proof=WebFlightNativeStability.compareRetained(a,b,SLIDER);
            check(proof.getJSONArray("ordinal_changes").length()==1&&!proof.getBoolean("original_node_ref_rebound"),"ordinal-only proof");
        });
        test("retained_target_semantics_change_rejected",()->{JSONArray a=retained(),b=copy(a);b.getJSONObject(0).put("text","改签");denied(()->WebFlightNativeStability.compareRetained(a,b,SLIDER));});
        test("retained_target_missing_rejected",()->{JSONArray a=retained(),b=copy(a);b.remove(0);denied(()->WebFlightNativeStability.compareRetained(a,b,SLIDER));});
        test("retained_duplicate_native_path_rejected",()->{JSONArray a=retained(),b=copy(a);b.put(copy(b.getJSONObject(0)).put("id","n99"));denied(()->WebFlightNativeStability.compareRetained(a,b,SLIDER));});
        test("retained_duplicate_ordinal_id_rejected",()->{JSONArray a=retained(),b=copy(a);b.getJSONObject(1).put("id","n8");denied(()->WebFlightNativeStability.compareRetained(a,b,SLIDER));});
        test("retained_carousel_membership_may_change",()->{JSONArray a=retained(),b=copy(a);b.remove(2);b.put(retainedNode(SLIDER+"/1","n4",""));check(WebFlightNativeStability.compareRetained(a,b,SLIDER).getBoolean("all_non_carousel_records_equal_except_ordinal_id"),"only carousel retained membership changes");});
        JSONObject result=new JSONObject().put("schema","hepta.flight-native-stability-synthetic-host.v1")
                .put("all_pass",true).put("cases",passed.size()).put("assertions",assertions).put("case_names",new JSONArray(passed))
                .put("synthetic_fixtures",true).put("actual_dom_or_native_snapshot_provided",false)
                .put("permit_or_service_dispatch_tested",false).put("phone_actions",0).put("phone_tested",false).put("business_verified",false);
        byte[] bytes=(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8);
        Files.write(output,bytes,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        System.out.println(result.toString());
    }
}
