package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/** Actual production observer bodies with explicitly synthetic Android IO.
 * The runner supplies a generated bridge; no phone, model or action is executed.
 */
public final class ObserverIntegrationHostTest {
    private static int assertions;
    private static final List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();
    private static void require(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static long number(Map<String,Object> value,String key){Object v=value.get(key);require(v instanceof Number,"numeric "+key);return ((Number)v).longValue();}
    @SuppressWarnings("unchecked")
    private static void run(String scenario,boolean publish,boolean form)throws Exception{
        Map<String,Object> result=ObserverPipelineHost.exerciseFormScenario(scenario);
        require(records.stream().noneMatch(r->scenario.equals(r.get("scenario"))),"unique scenario");
        require(number(result,"publications")== (publish?1:0),scenario+": publication outcome "+result);
        require(Boolean.TRUE.equals(result.get("original_deadline_preserved")),scenario+": original deadline");
        require(Boolean.TRUE.equals(result.get("all_graphs_closed")),scenario+": graph closure");
        require(Boolean.TRUE.equals(result.get("all_bitmaps_recycled")),scenario+": bitmap closure");
        require(Boolean.TRUE.equals(result.get("all_buffers_closed")),scenario+": hardware buffer closure");
        require(Boolean.TRUE.equals(result.get("workers_drained")),scenario+": serial worker drain");
        require(Boolean.TRUE.equals(result.get("no_action_work")),scenario+": no action work");
        require(number(result,"new_full_reads")>=3,scenario+": actual samples plus after census");
        if(publish){
            require(number(result,"new_png_files")==1,scenario+": one new persisted frame");
            require(number(result,"captured_at")==number(result,"actual_capture_requested_at"),scenario+": original capture age");
            Map<String,Object> evidence=(Map<String,Object>)result.get("capture_evidence");
            require(Boolean.FALSE.equals(evidence.get("grants_action_authority")),scenario+": no authority");
            require(Boolean.FALSE.equals(evidence.get("business_completion_verified")),scenario+": no business success");
            require(Boolean.FALSE.equals(evidence.get("same_instant_pixels_and_ax_claimed")),scenario+": no simultaneity");
            require(Boolean.TRUE.equals(evidence.get("fresh_action_validation_required")),scenario+": final action validation");
            require(Boolean.FALSE.equals(evidence.get("post_encoding_whole_graph_rechecked")),scenario+": no whole graph claim");
            require((form?"pre_encoding_form_pair_history":"pre_encoding_paired_history").equals(evidence.get("mode")),scenario+": correct mode");
            require(number(result,"new_window_checks")==1,scenario+": original current-window publication check");
            if(form){
                Map<String,Object> comparison=(Map<String,Object>)evidence.get("form_pair_comparison");
                require(comparison!=null,scenario+": full comparison recorded");
                require(Boolean.TRUE.equals(comparison.get("full_census_compared")),scenario+": full census");
                require(Boolean.FALSE.equals(comparison.get("changed_paths_truncated")),scenario+": all differences");
                require(Boolean.FALSE.equals(comparison.get("query_history_proved")),scenario+": no query history");
                require(Boolean.FALSE.equals(comparison.get("grants_action_authority")),scenario+": readonly comparison");
                require(Collections.singletonList("0/0/7/0").equals(comparison.get("changed_paths")),scenario+": exact changed path");
                require(Boolean.FALSE.equals(evidence.get("form_pair_events_after_census_completion_admitted")),scenario+": closed event interval");
                require(number(evidence,"pair_sealed_event_watermark")==number(evidence,"form_pair_target_events_at_census_completion"),scenario+": seal uses frozen census watermark");
                boolean immutable=false;try{comparison.put("grants_action_authority",true);}catch(UnsupportedOperationException expected){immutable=true;}
                require(immutable,scenario+": immutable nested proof");
            }else require(!evidence.containsKey("form_pair_comparison"),scenario+": old exact path unchanged");
        }else{
            require(number(result,"new_png_files")==0,scenario+": unpublished PNG removed");
            require(Boolean.TRUE.equals(result.get("original_observation_retained")),scenario+": refusal retains old frame");
        }
        result.put("expected_publication",publish);result.put("expected_form_mode",form);records.add(result);
        System.out.println("PASS "+scenario);
    }
    public static void main(String[] args)throws Exception{
        run("classified_complete_pair",true,true);
        run("known_target_event_during_census",true,true);
        run("unrelated_display_event",true,true);
        run("encoding_delay_keeps_original_capture_age",true,true);
        run("unchanged_pair_keeps_legacy_mode",true,false);
        for(String scenario:Arrays.asList(
                "protected_form_change","missing_child","visited_count_mismatch",
                "selection_checked_exception",
                "known_event_after_census_return","known_event_in_snapshot_adapter",
                "unknown_event_during_census","unknown_event_in_snapshot_adapter",
                "known_event_during_publication_check","unknown_event_during_publication_check",
                "known_event_after_publication_check","unknown_event_after_publication_check",
                "authorization_replaced","lease_retired","cancelled","original_deadline_expired",
                "partial_native_census","node_omission","child_omission","ime_visible",
                "missing_profile_proof","profile_token_replaced","window_id_replaced",
                "generation_replaced","owner_hash_replaced","census_task_replaced",
                "census_target_replaced","census_authorization_replaced","census_selection_replaced",
                "census_goal_replaced","native_nodes_missing","census_time_predates_request",
                "unsupported_installed_version","unsupported_base_apk","unsupported_owner_goal",
                "ordinary_user0_scope","xiaomi_scope","publication_window_replaced","read_before_replaced"
        ))run(scenario,false,false);
        Map<String,Object> report=new LinkedHashMap<String,Object>();
        report.put("schema","hepta.ctrip-form-observation-observer-cases.v1");
        report.put("all_pass",true);report.put("cases",records.size());report.put("assertions",assertions);
        List<String> names=new ArrayList<String>();for(Map<String,Object> record:records)names.add((String)record.get("scenario"));
        report.put("case_names",names);report.put("records",records);
        report.put("synthetic_android_io",true);report.put("phone_execution",false);
        report.put("model_executed",false);report.put("business_completion_verified",false);
        Files.write(Paths.get(args[0]),(new org.json.JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS observer cases="+records.size()+" assertions="+assertions);
    }
}
