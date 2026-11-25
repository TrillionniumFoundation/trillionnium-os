package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import org.json.JSONObject;

/** Actual Service publication pipeline; Android endpoints and event schedules are host fixtures. */
public final class SavedGraphHostTest {
    private static int assertions;
    private static final List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();
    private SavedGraphHostTest(){}
    private static void need(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static long number(Map<String,Object> m,String key){Object v=m.get(key);need(v instanceof Number,"numeric "+key);return ((Number)v).longValue();}
    @SuppressWarnings("unchecked")
    private static void run(String name,boolean publish,boolean baseline)throws Exception{
        Map<String,Object> r=ObserverPipelineHost.exerciseSavedGraphScenario(name);
        need(number(r,"publications")==(publish?1:0),name+": publication outcome "+r);
        need(Boolean.TRUE.equals(r.get("original_deadline_preserved")),name+": original 12 second request deadline");
        need(Boolean.TRUE.equals(r.get("workers_drained"))&&Boolean.TRUE.equals(r.get("all_graphs_closed"))
                &&Boolean.TRUE.equals(r.get("all_bitmaps_recycled"))&&Boolean.TRUE.equals(r.get("all_buffers_closed")),name+": all native IO resources drained");
        need(Boolean.TRUE.equals(r.get("no_action_work")),name+": no action or native cancellation work");
        need(Boolean.TRUE.equals(r.get("complete_original_pair_nodes")),name+": all 280 original nodes");
        need(Boolean.TRUE.equals(r.get("actual_nodes_equal_to_archive_before")),name+": all A node values preserved");
        need(Boolean.TRUE.equals(r.get("saved_c_is_not_published")),name+": C never replaces captured A");
        need(number(r,"new_full_reads")>=4,name+": existing full C read performed");
        Map<String,Object> diag=(Map<String,Object>)r.get("diagnostic");
        need(diag!=null&&new JSONObject(diag).toString().getBytes(StandardCharsets.UTF_8).length<=16384,name+": bounded actual diagnostics");
        Map<String,Object> events=(Map<String,Object>)diag.get("events");
        if(publish){
            need(Boolean.TRUE.equals(r.get("actual_nodes_equal_to_archive_after")),name+": complete actual C values preserved");
            need(number(r,"new_png_files")==1&&number(r,"form_history_files")==1,name+": one actual PNG and full history");
            need(Boolean.TRUE.equals(r.get("published_graph_is_original_a")),name+": publishes actual original A Graph");
            need(number(r,"captured_at")==number(r,"original_capture_requested_at"),name+": original image age");
            need(number(r,"capture_evidence_bytes")<=8192,name+": unchanged metadata cap");
            Map<String,Object> e=(Map<String,Object>)r.get("capture_evidence");
            need("post_encoding_form_pair_history".equals(e.get("mode")),name+": exact historical mode");
            need(Boolean.FALSE.equals(e.get("grants_action_authority"))&&Boolean.FALSE.equals(e.get("business_completion_verified"))
                    &&Boolean.FALSE.equals(e.get("same_instant_pixels_and_ax_claimed"))&&Boolean.TRUE.equals(e.get("fresh_action_validation_required")),name+": no new authority");
            need(Boolean.FALSE.equals(e.get("post_encoding_whole_graph_rechecked"))
                    &&Boolean.FALSE.equals(e.get("post_encoding_complete_native_graph_rechecked")),name+": not a whole graph equality claim");
            need(number(e,"post_encoding_complete_native_graph_completed_event_watermark")==number(e,"publication_check_event_watermark"),name+": actual C event closure");
            Map<String,Object> compact=(Map<String,Object>)e.get("post_encoding_form_pair_comparison");
            need(compact!=null&&!compact.containsKey("entered_open_read_permit"),name+": ordinary read has no OPEN permit");
            Map<String,Object> history=(Map<String,Object>)r.get("form_history");
            Map<String,Object> proof=(Map<String,Object>)history.get("post_encoding");
            Map<String,Object> reference=(Map<String,Object>)compact.get("complete_comparison_artifact");
            need(r.get("form_history_sha256").equals(reference.get("sha256"))&&number(r,"form_history_bytes")==number(reference,"bytes"),name+": actual full artifact bytes bound");
            need(Boolean.TRUE.equals(proof.get("full_census_compared"))&&Boolean.FALSE.equals(proof.get("changed_paths_truncated")),name+": complete original comparison");
            need(Arrays.asList("0/0/9","0/0/9/0","0/0/9/0/0","0/0/9/3/1","0/0/9/3/2","0/0/9/3/3").equals(proof.get("changed_paths")),name+": exactly the actual six differences");
            need(Boolean.FALSE.equals(proof.get("grants_action_authority"))&&Boolean.FALSE.equals(proof.get("query_history_proved")),name+": classification is not query evidence");
            need(!proof.containsKey("entered_open_read_permit"),name+": full proof has no entered OPEN authority");
        }else{
            need(number(r,"new_png_files")==0&&number(r,"form_history_files")==0,name+": unpublished PNG and history removed");
            need(Boolean.TRUE.equals(r.get("original_observation_retained")),name+": old current frame retained");
        }
        if(!baseline&&"unsealed_boundary_pair".equals(name)){
            need(number(events,"SAVED_GRAPH_UNSEALED_CHANGED")==1&&!events.containsKey("SAVED_GRAPH_SEALED_CONTENT_CHANGED"),name+": actual unsealed diagnostic");
            need(number(r,"read_capture_failures")==1,name+": new diagnostic does not double-count refusal");
        }
        if(!baseline&&"protected_date_changed".equals(name)){
            need(number(events,"SAVED_GRAPH_SEALED_CONTENT_CHANGED")==1&&!events.containsKey("SAVED_GRAPH_UNSEALED_CHANGED"),name+": actual sealed diagnostic");
            need(number(r,"read_capture_failures")==1,name+": existing refusal count unchanged");
        }
        if(name.endsWith("during_comparison"))need(number(r,"comparison_endpoint_hooks")==1,name+": actual comparator snapshot endpoint reached");
        if(name.endsWith("during_history_persist"))need(number(r,"persist_endpoint_hooks")==1,name+": actual artifact hash endpoint reached");
        r.put("expected_publication",publish);records.add(r);System.out.println("PASS "+name);
    }
    public static void main(String[] args)throws Exception{
        need(args.length==2,"output and baseline|candidate required");
        boolean baseline="baseline".equals(args[1]);need(baseline||"candidate".equals(args[1]),"known phase");
        if(baseline){
            run("actual_280_complete_pair",false,true);
            run("content_during_census",false,true);
        }else{
            for(String name:Arrays.asList("actual_280_complete_pair","content_during_census","unrelated_display_during_census"))run(name,true,false);
            for(String name:Arrays.asList("unsealed_boundary_pair","unknown_during_encode","boundary_during_encode","untyped_counter_increment",
                    "unknown_during_census","boundary_during_census","content_after_census_endpoint",
                    "content_during_comparison","unknown_during_comparison","content_during_history_persist","unknown_during_history_persist",
                    "content_before_publication","unknown_before_publication","boundary_before_publication",
                    "wrong_current","missing_read_identity","rejected_read_identity","no_read_before","initial_mode",
                    "lease_closed","authorization_replaced","cancelled","deadline_reached",
                    "protected_date_changed","protected_ancestor_changed","window_changed","owner_changed","generation_changed",
                    "profile_token_changed","profile_missing","omitted_census","missing_node","target_changed","goal_changed",
                    "ime_visible","capture_clock_before_request"))run(name,false,false);
        }
        List<String> names=new ArrayList<String>();for(Map<String,Object> r:records)names.add((String)r.get("scenario"));
        need(new HashSet<String>(names).size()==names.size(),"unique named cases");
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.ctrip-saved-graph-producer-cases.v1");out.put("all_pass",true);out.put("phase",args[1]);
        out.put("cases",records.size());out.put("assertions",assertions);out.put("case_names",names);out.put("records",records);
        out.put("actual_archived_nodes",true);out.put("synthetic_android_io_profile_lease_clock_events",true);
        out.put("actual_failure_branch_proved",false);out.put("historical_capture_clock_reconstructed",false);
        out.put("historical_event_watermarks_reconstructed",false);out.put("phone_operations",0);
        out.put("actual_65b5_success_claimed",false);out.put("business_completion_verified",false);
        Files.write(Paths.get(args[0]),(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("SAVED-GRAPH-CASES "+records.size()+" assertions="+assertions);
    }
}
