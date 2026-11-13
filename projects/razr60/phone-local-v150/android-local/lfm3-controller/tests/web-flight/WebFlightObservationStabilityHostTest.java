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
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;

/** Pure read-only policy tests. Real PhoneObservation serialization and DOM/geometry
 * replay operate on synthetic fixtures; no private service token or action Permit is fabricated. */
public final class WebFlightObservationStabilityHostTest {
    private static final String TASK="11111111111111111111111111111111";
    private static final String TARGET="0/0/1/0",SLIDER="0/0/0",HELPER=WebEvidenceProtocol.HELPER_PACKAGE;
    private static final List<String> names=new ArrayList<String>();private static int assertions;
    private interface Case { void run()throws Exception; }
    private interface Mutation { void change(Fixture f)throws Exception; }
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Case run)throws Exception{run.run();names.add(name);}
    private static void denied(Case run)throws Exception{
        boolean rejected=false;try{run.run();}catch(IllegalArgumentException|IllegalStateException|org.json.JSONException expected){rejected=true;}
        check(rejected,"changed observation proof was accepted");
    }
    private static void negative(String name,Mutation mutate)throws Exception{test(name,()->{Fixture f=new Fixture();mutate.change(f);denied(()->f.proof());});}
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static String repeat(char value,int count){StringBuilder b=new StringBuilder();while(count-->0)b.append(value);return b.toString();}
    private static Object fixture(Class<?> owner,String name,Class<?>[] types,Object...args)throws Exception{
        Method m=owner.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException failure){Throwable cause=failure.getCause();if(cause instanceof Exception)throw (Exception)cause;throw failure;}
    }
    private static JSONObject at(JSONArray rows,String path)throws Exception{
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);
        throw new IllegalArgumentException("synthetic path unavailable");
    }
    private static JSONObject dom()throws Exception{
        JSONObject full=(JSONObject)fixture(WebFlightEvidenceHostTest.class,"dom",new Class<?>[0]);
        JSONObject policy=(JSONObject)fixture(WebFlightNativeStabilityHostTest.class,"dom",new Class<?>[0]);
        JSONObject template=full.getJSONArray("nodes").getJSONObject(0);JSONArray rows=new JSONArray();
        JSONArray values=policy.getJSONArray("nodes");
        for(int i=0;i<values.length();i++){
            JSONObject row=copy(template),source=values.getJSONObject(i);java.util.Iterator<String> keys=source.keys();
            while(keys.hasNext()){String key=keys.next();row.put(key,source.get(key));}rows.put(row);
        }
        full.put("nodes",rows).put("visited",rows.length()).put("viewport_css_pixels",new JSONArray(new int[]{400,700}))
                .put("layout_viewport_css_pixels",new JSONArray(new int[]{400,700})).put("document_extent_css_pixels",new JSONArray(new int[]{400,700}));
        full.getJSONObject("visual_viewport").put("height",700);return full;
    }
    private static JSONArray nativeRows(int ad)throws Exception{
        return (JSONArray)fixture(WebFlightNativeStabilityHostTest.class,"nativeTree",new Class<?>[]{int.class,int.class},ad,100);
    }
    private static JSONObject frame(JSONArray nativeRows,int ad,boolean after,JSONObject binding)throws Exception{
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        String[] paths={TARGET,"0/0/1",SLIDER+"/"+ad};
        for(int i=0;i<paths.length;i++){
            JSONObject row=at(nativeRows,paths[i]);JSONArray box=row.getJSONArray("bounds");
            nodes.add(new PhoneObservation.Node("n"+(i+(after?1:0)),HELPER,row.getString("class"),row.getString("view_id"),
                    row.getString("text"),row.getString("description"),new Rect(box.getInt(0),box.getInt(1),box.getInt(2),box.getInt(3)),
                    row.getBoolean("clickable"),false,false,true,false,false,ObservedChildText.notApplicable(),
                    ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.ABSENT,null,false,
                    repeat('a',64),paths[i],row.getString("parent_class")));
        }
        JSONObject selected=new JSONObject().put("mode","background").put("allowed_packages",new JSONArray().put(HELPER))
                .put("bootstrap_package",HELPER).put("bootstrap_source","owner_selected_initial_app")
                .put("bootstrap_model_issued",false).put("home_allowed",false).put("main_display_fallback",false);
        PhoneObservation.CollectionStats counters=new PhoneObservation.CollectionStats(1200,100,30000,
                nativeRows.length(),nodes.size(),100,0,0,0,0,after?15:10);
        PhoneObservation frame=new PhoneObservation(after?repeat('3',32):repeat('2',32),HELPER,after?1800:900,
                400,700,0,71,new Rect(0,0,400,700),null,repeat(after?'d':'c',64),repeat(after?'f':'e',64),
                new ObservationState(repeat(after?'b':'a',64),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,400,700},"android.widget.FrameLayout",1,7,new int[]{0,0,400,700},"synthetic helper"),
                false,nodes,binding.getJSONObject("background").getString("generation"),HELPER,Collections.singletonList(HELPER),
                counters,selected,binding.getString("owner_sha256"));
        return frame.toJson();
    }
    private static JSONObject capture(JSONObject dom,boolean last)throws Exception{
        JSONObject packet=(JSONObject)fixture(WebFlightEvidenceHostTest.class,"captured",new Class<?>[0]);
        JSONObject c=packet.getJSONObject("capture");long start=last?2000:1000;
        c.put("actual_window_id",71).put("started_elapsed_ms",start).put("ended_elapsed_ms",start+10)
                .put("challenge",repeat(last?'f':'e',64)).put("webview_bounds_screen_pixels",new JSONArray(new int[]{0,0,400,700}));
        JSONArray samples=c.getJSONObject("capture_geometry").getJSONArray("samples");
        for(int i=0;i<samples.length();i++)samples.getJSONObject(i).getJSONObject("native")
                .put("sampled_elapsed_ms",start+1+i).put("actual_window_id",71)
                .put("bounds_screen_pixels",new JSONArray(new int[]{0,0,400,700}))
                .put("global_visible_rect_pixels",new JSONArray(new int[]{0,0,400,700}));
        fixture(WebFlightEvidenceHostTest.class,"wireFixtureStability",new Class<?>[]{JSONObject.class,JSONObject.class,JSONObject.class},
                c,dom,c.getJSONObject("binding"));return c;
    }
    private static final class Fixture {
        String task=TASK;final JSONArray beforeNative,afterNative;final JSONObject before,after,first,last;
        Fixture()throws Exception{
            JSONObject dom=dom();first=capture(dom,false);last=capture(dom,true);
            beforeNative=nativeRows(0);afterNative=nativeRows(1);
            before=frame(beforeNative,0,false,first.getJSONObject("binding"));after=frame(afterNative,1,true,first.getJSONObject("binding"));
        }
        JSONObject proof()throws Exception{return WebFlightNativeStability.compareObservationBracket(task,before,beforeNative,after,afterNative,first,last,TARGET);}
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"one new output path required");Path out=Paths.get(args[0]);check(!Files.exists(out),"create-only result");
        test("complete_home_bracket_with_changed_carousel_is_readonly",()->{
            Fixture f=new Fixture();JSONObject p=f.proof();
            check(!f.before.getString("observation_state_sha256").equals(f.after.getString("observation_state_sha256")),"source AX state hashes really differ");
            check(p.getBoolean("all_four_dom_raws_equal")&&p.getBoolean("complete_native_snapshot_structure_replayed"),"full DOM and native predicates executed");
            check(!p.getBoolean("action_permit_created")&&!p.getBoolean("business_verified")&&!p.getBoolean("fully_unoccluded_claimed")
                    &&!p.getBoolean("coordinates_used_for_input"),"read-only policy grants no action or business proof");
            check(p.getJSONObject("native").getJSONObject("retained_node_pairing").getJSONArray("ordinal_changes").length()==2,
                    "unchanged non-carousel semantic rows keep actual path correspondence despite ordinal changes");
        });
        negative("foreign_task_rejected",f->f.task=repeat('9',32));
        negative("non_helper_frame_rejected",f->f.after.put("package","other.app"));
        negative("ime_visible_rejected",f->f.after.put("ime_visible",true));
        negative("truncated_frame_rejected",f->f.after.put("nodes_truncated",true));
        negative("changed_window_title_rejected",f->f.after.getJSONObject("window").put("title","changed"));
        negative("changed_background_selection_rejected",f->f.after.getJSONObject("background_session").getJSONArray("allowed_packages").put("other.app"));
        negative("pending_native_nodes_rejected",f->f.after.getJSONObject("collection").put("pending_nodes_at_stop",1));
        negative("native_visited_count_mismatch_rejected",f->f.after.getJSONObject("collection").put("visited_nodes",1));
        negative("retained_count_mismatch_rejected",f->f.after.getJSONObject("collection").put("retained_nodes",1));
        negative("collection_counter_drift_rejected",f->f.after.getJSONObject("collection").put("visit_limit",1201));
        negative("native_root_metadata_mismatch_rejected",f->at(f.afterNative,"0").getJSONArray("bounds").put(3,699));
        negative("changed_capture_binding_rejected",f->f.last.getJSONObject("binding").put("task_id",repeat('8',32)));
        negative("booking_page_is_not_home_exception",f->{f.first.put("current_native_url","https://m.csair.com/booking_new/");f.last.put("current_native_url","https://m.csair.com/booking_new/");});
        negative("observed_link_navigation_rejected",f->f.last.put("observed_link_navigation",new JSONObject()));
        negative("helper_process_drift_rejected",f->f.last.put("helper_pid",124));
        negative("navigation_epoch_drift_rejected",f->f.last.put("navigation_epoch",8));
        negative("webview_instance_drift_rejected",f->f.last.put("webview_instance","another-instance"));
        negative("overlapping_capture_intervals_rejected",f->f.last.put("started_elapsed_ms",1005));
        negative("byte_different_fourth_dom_rejected",f->f.last.put("dom_raw_utf8",f.last.getString("dom_raw_utf8")+" "));
        negative("native_target_semantics_change_rejected",f->at(f.afterNative,TARGET).put("text","支付"));
        negative("retained_target_semantics_change_rejected",f->f.after.getJSONArray("nodes").getJSONObject(0).put("text","支付"));
        negative("clipped_native_webview_rejected",f->f.last.getJSONObject("capture_geometry").getJSONArray("samples").getJSONObject(0)
                .getJSONObject("native").put("global_visible_rect_pixels",new JSONArray(new int[]{0,0,399,700})));
        negative("omitted_non_retained_native_child_rejected_even_with_matching_counts",f->{
            for(JSONArray rows:new JSONArray[]{f.beforeNative,f.afterNative}){
                for(int i=0;i<rows.length();i++)if((SLIDER+"/7/0").equals(rows.getJSONObject(i).getString("path"))){rows.remove(i);break;}
            }
            f.after.getJSONObject("collection").put("visited_nodes",f.afterNative.length());
            f.before.getJSONObject("collection").put("visited_nodes",f.beforeNative.length());
        });
        JSONObject result=new JSONObject().put("schema","hepta.flight-observation-bracket-synthetic.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("synthetic_fixtures",true).put("actual_phone_observation_serialization",true)
                .put("actual_dom_stability_and_geometry_replay",true).put("actual_service_snapshot_or_binder_tested",false)
                .put("action_permit_created",false).put("phone_operations",0).put("business_verified",false);
        Files.write(out,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        System.out.println(result.toString());
    }
}
