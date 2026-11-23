package org.trillionnium.hepta.local;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.*;

/** Real immutable DOM/retained AX fixtures plus explicitly synthetic complete native boundary graphs. */
public final class ShoppingReadonlyObservationHost {
    interface Checked { void run() throws Exception; }
    static int cases=0,assertions=0; static final JSONArray passed=new JSONArray();
    static JSONObject a,b,da,db,fa,fb; static WebMiActionRegion region;
    static final String TARGET="0/0/0",REC="0/0/1";
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void pass(String name){cases++;passed.put(name);}
    static void accepts(String name,Checked test)throws Exception{test.run();pass(name);}
    static void rejects(String name,Checked test)throws Exception{
        boolean rejected=false;try{test.run();}catch(IllegalArgumentException|JSONException expected){rejected=true;}
        check(rejected,name+" must reject");pass(name);
    }
    static JSONObject obj(JSONObject x){return new JSONObject(x.toString());}
    static JSONArray arr(JSONArray x){return new JSONArray(x.toString());}
    static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    static JSONObject node(JSONObject dom,String path){
        JSONArray n=dom.getJSONArray("nodes");
        for(int i=0;i<n.length();i++)if(path.equals(n.getJSONObject(i).getString("path")))return n.getJSONObject(i);
        throw new AssertionError("missing test node "+path);
    }
    static JSONObject by(JSONObject dom,String field,String value){
        JSONArray n=dom.getJSONArray("nodes");JSONObject found=null;
        for(int i=0;i<n.length();i++)if(value.equals(n.getJSONObject(i).opt(field))){
            if(found!=null)throw new AssertionError("ambiguous test node");found=n.getJSONObject(i);
        }
        if(found==null)throw new AssertionError("missing test "+field);return found;
    }
    static JSONObject nativeNode(JSONArray rows,String path){
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);
        throw new AssertionError("missing native test node");
    }
    static void recount(JSONObject dom){
        long count=0;JSONArray rows=dom.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++)for(String k:new String[]{"id","role","name","aria_label","href_raw","href_resolved","link_target",
                "item_type","item_prop","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed","text","value"}){
            Object v=rows.getJSONObject(i).get(k);if(v instanceof String)count+=((String)v).length();
        }
        Object meta=dom.get("viewport_meta_content");if(meta instanceof String)count+=((String)meta).length();
        dom.put("text_utf16_units",count);dom.put("visited",rows.length());
    }
    static JSONObject style(JSONObject d,String section,String path){
        JSONArray all=d.getJSONObject(section).getJSONArray("style_contexts");
        for(int i=0;i<all.length();i++)if(path.equals(all.getJSONObject(i).getString("path")))return all.getJSONObject(i);
        throw new AssertionError("missing style");
    }
    static JSONObject n(String path,String clazz,String parent,int children,int[] box,String text,String description,String id,boolean click){
        return new JSONObject().put("path",path).put("parent_class",parent).put("package",WebEvidenceProtocol.HELPER_PACKAGE)
                .put("window_id",3679).put("class",clazz).put("view_id",id).put("text",text).put("description",description)
                .put("bounds",new JSONArray(box)).put("visible",true).put("enabled",true).put("clickable",click)
                .put("editable",false).put("scrollable",false).put("password",false).put("focused",false).put("children",children);
    }
    static JSONArray nativeGraph(boolean after)throws Exception{
        int[] web=WebNativeGeometry.read(a,da,36,3679).bounds;
        return new JSONArray()
            .put(n("0","android.widget.FrameLayout","",1,new int[]{0,0,720,1280},"","","",false))
            .put(n("0/0","android.webkit.WebView","android.widget.FrameLayout",2,web,"","","",false))
            .put(n(TARGET,"android.view.View","android.webkit.WebView",3,new int[]{0,296,171,546},"","Xiaomi路由器AX3000T 白色 159元 199元","",true))
            .put(n(TARGET+"/0","android.widget.Image","android.view.View",0,new int[]{0,296,171,430},"","","",false))
            .put(n(TARGET+"/1","android.widget.TextView","android.view.View",0,new int[]{8,440,162,460},"Xiaomi路由器AX3000T 白色","","",false))
            .put(n(TARGET+"/2","android.view.View","android.view.View",2,new int[]{20,480,150,520},"","","",false))
            .put(n(TARGET+"/2/0","android.widget.TextView","android.view.View",0,new int[]{20,480,70,520},"159元","","",false))
            .put(n(TARGET+"/2/1","android.view.View","android.view.View",0,new int[]{80,480,150,520}," 199元","","",false))
            .put(n(REC,"android.view.View","android.webkit.WebView",1,new int[]{0,650,711,827},"","","J_recommend_search",false))
            .put(n(REC+"/0","android.widget.TextView","android.view.View",0,new int[]{100,660,200,800},after?"明确的测试推荐B":"明确的测试推荐A","","",false));
    }
    static JSONObject syntheticFrame(JSONArray nativeRows,boolean after){
        JSONObject out=obj(fa);out.put("observation_id",after?"synthetic-after":"synthetic-before");
        JSONArray retained=new JSONArray();long text=0;
        for(int i=0;i<nativeRows.length();i++){
            JSONObject n=nativeRows.getJSONObject(i);
            retained.put(new JSONObject().put("id","n"+i).put("text",n.get("text")).put("description",n.get("description"))
                .put("child_text","").put("native_tree_position",new JSONObject().put("path",n.get("path"))));
            text+=n.getString("text").length()+n.getString("description").length();
        }
        out.put("nodes",retained);JSONObject c=out.getJSONObject("collection");
        c.put("visited_nodes",nativeRows.length()).put("retained_nodes",retained.length()).put("retained_text_utf16",text);
        return out;
    }
    static void captureReject(String name,JSONObject first,JSONObject last){
        check(!WebShoppingObservationStability.supportsCaptures(first,last),name+" must reject");pass(name);
    }
    public static void main(String[] args)throws Exception{
        Path fixtures=Paths.get(args[0]);
        a=read(fixtures.resolve("raw-first.json")).getJSONObject("capture");
        b=read(fixtures.resolve("raw-last.json")).getJSONObject("capture");
        da=WebEvidenceJson.parseDom(a.getString("dom_raw_utf8"));db=WebEvidenceJson.parseDom(b.getString("before_dom_raw_utf8"));
        fa=read(fixtures.resolve("ax-first.json")).getJSONObject("observation");
        fb=read(fixtures.resolve("ax-last.json")).getJSONObject("observation");
        region=WebMiActionRegion.read(da);
        rejects("actual_original_generic_cross_capture_proof_still_rejects",()->WebDomStability.evaluate(
                a.getString("dom_raw_utf8"),b.getString("before_dom_raw_utf8"),WebMiActionRegion.POLICY));
        accepts("actual_104_DOM_changes_are_explicit_readonly_scope",()->{
            JSONObject p=WebShoppingObservationStability.compareDom(da,db);
            check(p.getJSONArray("outside_changes").length()==104,"all 104 actual node differences retained");
            check(p.getJSONArray("outside_clip_style_changes").length()==1,"one actual bounded loading style scope");
            check(!p.getBoolean("grants_action_authority")&&!p.getBoolean("business_verified")&&!p.getBoolean("detail_price_verified"),"read only");
            check(p.getBoolean("each_dom_counts_recomputed"),"independent actual counts");
        });
        accepts("all_four_actual_capture_DOMs_keep_original_per_capture_proof",()->check(
                WebShoppingObservationStability.supportsCaptures(a,b),"actual 4-DOM capture eligibility"));
        accepts("actual_387_391_retained_AX_recommendation_changes_are_explicit",()->{
            check(fa.getJSONArray("nodes").length()==387&&fb.getJSONArray("nodes").length()==391,"original retained node counts");
            JSONObject p=WebShoppingObservationStability.compareRetained(fa.getJSONArray("nodes"),fb.getJSONArray("nodes"),"0/2/0/0/0/3/6");
            check(p.getJSONArray("outside_recommendation_retained_changes").length()>0,"actual changes retained");
            check(!p.getBoolean("recommendation_child_text_completeness_claimed"),"outside child text is not complete authority");
        });
        rejects("actual_retained_AX_cannot_substitute_complete_native_snapshot",()->WebShoppingObservationStability.compareObservationBracket(
                a.getJSONObject("binding").getString("task_id"),fa,fa.getJSONArray("nodes"),fb,fb.getJSONArray("nodes"),a,b,"0/2/0/0/0/3/4/1/0"));
        rejects("changed_current_card_price_rejected_even_with_correct_counter",()->{
            JSONObject x=obj(db);node(x,region.currentPricePath).put("text","158元");recount(x);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_card_title_rejected",()->{
            JSONObject x=obj(db);node(x,region.modelPath).put("text","Xiaomi路由器AX3000T 黑色");recount(x);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_card_link_rejected",()->{
            JSONObject x=obj(db);node(x,region.anchorPath).put("href_resolved","https://www.mi.com/shop/buy?product_id=1230803767&cfrom=search");recount(x);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_card_bounds_rejected",()->{
            JSONObject x=obj(db);JSONArray box=node(x,region.rootPath).getJSONArray("rect_css_pixels");box.put(0,box.getDouble(0)+1);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_card_ancestor_bounds_rejected",()->{
            JSONObject x=obj(db);String parent=region.rootPath.substring(0,region.rootPath.lastIndexOf('/'));
            JSONArray box=node(x,parent).getJSONArray("rect_css_pixels");box.put(2,box.getDouble(2)+1);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_selected_CSS_context_rejected",()->{
            JSONObject x=obj(db);style(x,"action_region_observations",region.anchorPath).put("opacity","0.5");
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("incomplete_region_hit_observations_rejected",()->{
            JSONObject x=obj(db);x.getJSONObject("action_region_observations").put("complete",false);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_global_viewport_rejected",()->{
            JSONObject x=obj(db);x.getJSONArray("viewport_css_pixels").put(0,1242);WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_global_device_pixel_ratio_rejected",()->{
            JSONObject x=obj(db);x.put("device_pixel_ratio",2);WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("unrecorded_outside_semantic_text_rejected",()->{
            JSONObject x=obj(db);by(x,"id","J_miniCartMenu").put("text","页面其他价格");recount(x);WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("changed_recommendation_href_rejected",()->{
            JSONObject x=obj(db);String rec=by(x,"id","J_recommend_search").getString("path");JSONObject changed=null;
            JSONArray rows=x.getJSONArray("nodes");for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);
                if(row.getString("path").startsWith(rec+"/")&&!row.isNull("href_resolved")){changed=row;break;}}
            check(changed!=null,"real recommendation link exists");changed.put("href_resolved","https://evil.invalid/");recount(x);
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("recommendation_geometry_overlapping_card_rejected",()->{
            JSONObject x=obj(db);String rec=by(x,"id","J_recommend_search").getString("path");
            JSONObject changed=node(x,rec+"/0");changed.put("rect_css_pixels",new JSONArray(node(da,region.rootPath).getJSONArray("rect_css_pixels").toString()));
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("unknown_clipping_style_change_rejected",()->{
            JSONObject x=obj(db);style(x,"clipping_context_observations","0").put("filter","blur(1px)");
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("header_loader_horizontal_transform_rejected",()->{
            JSONObject x=obj(db);String menu=by(x,"id","J_miniCartMenu").getString("path");
            style(x,"clipping_context_observations",menu+"/0/0/0").put("transform","matrix(1, 0, 0, 0.5, 1, 0)");
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("header_loader_expanding_scale_rejected",()->{
            JSONObject x=obj(db);String menu=by(x,"id","J_miniCartMenu").getString("path");
            style(x,"clipping_context_observations",menu+"/0/0/0").put("transform","matrix(1, 0, 0, 1.1, 0, 0)");
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("header_loader_new_pseudo_content_rejected",()->{
            JSONObject x=obj(db);String menu=by(x,"id","J_miniCartMenu").getString("path");
            style(x,"clipping_context_observations",menu+"/0/0/0").getJSONObject("pseudo_after").put("content","\"159元\"");
            WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("DOM_text_counter_not_normalized_rejected",()->{
            JSONObject x=obj(db);x.put("text_utf16_units",x.getLong("text_utf16_units")+1);WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("DOM_visited_counter_not_normalized_rejected",()->{
            JSONObject x=obj(db);x.put("visited",x.getInt("visited")-1);WebShoppingObservationStability.compareDom(da,x);
        });
        rejects("DOM_record_membership_loss_rejected",()->{
            JSONObject x=obj(db);x.getJSONArray("nodes").remove(x.getJSONArray("nodes").length()-1);recount(x);
            WebShoppingObservationStability.compareDom(da,x);
        });
        JSONObject poison=obj(b);poison.put("observer_script_sha256",String.join("",Collections.nCopies(64,"0")));
        captureReject("unrecognized_observer_accounting_rejected",a,poison);
        poison=obj(b);poison.put("navigation_epoch",b.getLong("navigation_epoch")+1);
        captureReject("capture_navigation_epoch_change_rejected",a,poison);
        poison=obj(b);poison.getJSONObject("binding").put("task_id","another-task");
        captureReject("capture_task_binding_change_rejected",a,poison);
        poison=obj(b);poison.put("before_dom_raw_utf8",b.getString("before_dom_raw_utf8")+" ");
        captureReject("per_capture_original_raw_hash_stays_required",a,poison);
        poison=obj(b);poison.put("started_elapsed_ms",a.getLong("ended_elapsed_ms")-1);
        captureReject("capture_order_reversal_rejected",a,poison);
        JSONArray na=nativeGraph(false),nb=nativeGraph(true);
        JSONObject sa=syntheticFrame(na,false),sb=syntheticFrame(nb,true);
        accepts("explicit_synthetic_complete_native_positive",()->{
            JSONObject p=WebShoppingObservationStability.compareNative(na,nb,TARGET);
            check(p.getBoolean("complete_native_membership_equal")&&!p.getBoolean("action_permit_created"),"native readonly scope");
        });
        accepts("actual_four_DOMs_with_explicit_synthetic_native_full_bracket",()->{
            JSONObject p=WebShoppingObservationStability.compareObservationBracket(a.getJSONObject("binding").getString("task_id"),sa,na,sb,nb,a,b,TARGET);
            check(p.getBoolean("complete_native_snapshot_structure_replayed"),"complete synthetic structural proof");
            check(!p.getBoolean("grants_action_authority")&&!p.getBoolean("coordinates_used_for_input"),"no input authority");
        });
        rejects("complete_native_child_omission_rejected",()->{
            JSONArray x=arr(nb);x.remove(7);WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("native_target_move_rejected",()->{
            JSONArray x=arr(nb);nativeNode(x,TARGET).getJSONArray("bounds").put(0,1);WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("native_ancestor_metadata_change_rejected",()->{
            JSONArray x=arr(nb);nativeNode(x,"0/0").put("description","changed");WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("recommendation_native_focus_change_rejected",()->{
            JSONArray x=arr(nb);nativeNode(x,REC+"/0").put("focused",true);WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("recommendation_native_class_change_rejected",()->{
            JSONArray x=arr(nb);nativeNode(x,REC+"/0").put("class","android.widget.EditText");WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("recommendation_native_overlaps_target_rejected",()->{
            JSONArray x=arr(nb);nativeNode(x,REC+"/0").put("bounds",new JSONArray(new int[]{0,296,171,546}));WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("mixed_native_window_rejected",()->{
            JSONArray x=arr(nb);nativeNode(x,REC+"/0").put("window_id",3680);WebShoppingObservationStability.compareNative(na,x,TARGET);
        });
        rejects("incomplete_observation_pending_nodes_rejected",()->{
            JSONObject x=obj(sb);x.getJSONObject("collection").put("pending_nodes_at_stop",1);
            WebShoppingObservationStability.compareObservationBracket(a.getJSONObject("binding").getString("task_id"),sa,na,x,nb,a,b,TARGET);
        });
        rejects("native_collection_visited_mismatch_rejected",()->{
            JSONObject x=obj(sb);x.getJSONObject("collection").put("visited_nodes",nb.length()+1);
            WebShoppingObservationStability.compareObservationBracket(a.getJSONObject("binding").getString("task_id"),sa,na,x,nb,a,b,TARGET);
        });
        rejects("native_collection_retained_text_mismatch_rejected",()->{
            JSONObject x=obj(sb);x.getJSONObject("collection").put("retained_text_utf16",1);
            WebShoppingObservationStability.compareObservationBracket(a.getJSONObject("binding").getString("task_id"),sa,na,x,nb,a,b,TARGET);
        });
        rejects("observation_generation_change_rejected",()->{
            JSONObject x=obj(sb);x.getJSONObject("background_session").put("generation","another-generation");
            WebShoppingObservationStability.compareObservationBracket(a.getJSONObject("binding").getString("task_id"),sa,na,x,nb,a,b,TARGET);
        });
        rejects("actual_nonrecommendation_retained_price_change_rejected",()->{
            JSONArray x=arr(fb.getJSONArray("nodes"));
            for(int i=0;i<x.length();i++){JSONObject row=x.getJSONObject(i);if("0/2/0/0/0/3/4/1/0".equals(row.getJSONObject("native_tree_position").getString("path"))){
                row.put("description","Xiaomi路由器AX3000T 白色 158元 199元");break;}}
            WebShoppingObservationStability.compareRetained(fa.getJSONArray("nodes"),x,"0/2/0/0/0/3/6");
        });
        System.out.println(new JSONObject().put("all_pass",true).put("cases",cases).put("assertions",assertions).put("case_names",passed)
                .put("actual_dom_and_retained_ax",true).put("complete_native_graphs","explicit synthetic boundaries only")
                .put("phone_actions",0).put("actual_native_snapshot_or_ipc_verified",false).put("business_verified",false));
    }
}
