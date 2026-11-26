package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import org.json.JSONObject;

/** Actual Service worker/accept/classifier/publication over explicitly synthetic
 * Android and existing Session IO boundaries. No entered action or phone claim. */
public final class CtripFormSamplingHostTest {
    private static int assertions;
    static java.nio.file.Path historyRoot;
    static void need(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    private static final List<String> SCENARIOS=Arrays.asList(
            "complete_pair",
            "archived_complete_pair",
            "historic_boundary_future_content",
            "same_keys",
            "ordinary_scope",
            "initial_scope",
            "native_ax_scope",
            "first_incomplete",
            "first_not_form",
            "protected_date",
            "protected_query",
            "ancestor_changed",
            "direct_sibling_clickable_readonly_control",
            "nested_clickable_child_rejected",
            "missing_child",
            "pending_child",
            "truncated_graph",
            "ime_unknown",
            "window_changed",
            "generation_changed",
            "profile_token_changed",
            "read_clock_reversed",
            "missing_graph",
            "typed_child_failure",
            "event_content",
            "event_other_display",
            "event_unknown",
            "event_untyped",
            "event_boundary",
            "event_foreign_window",
            "event_foreign_package",
            "queued_content",
            "queued_boundary",
            "authorization_replaced",
            "controller_replaced",
            "background_released",
            "cancelled",
            "permit_retired",
            "installed_version_changed",
            "unsupported_goal",
            "parallel_action",
            "settle_expiry",
            "pure_value_lifecycle",
            "capture_retry_clears_pair",
            "classified_interval",
            "equal_key_interval",
            "diagnostic_bounds",
            "late_window_failure",
            "late_unknown_event",
            "history_limit_exact",
            "history_limit_exceeded",
            "queued_content_diagnostic_finished"
    );
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("one fresh output required");
        historyRoot=Paths.get(args[0]).toAbsolutePath().getParent().resolve("sampling-history");
        Files.createDirectory(historyRoot);
        List<String> names=new ArrayList<String>();List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
        int passed=0;
        try{
            for(String scenario:SCENARIOS){
                String name="sampling_worker_"+scenario;
                need(!names.contains(name),"unique scenario");names.add(name);
                Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
                int before=assertions;
                try{
                    row.put("evidence",ObserverPipelineHost.exerciseFormSampling(scenario));
                    row.put("pass",true);passed++;System.out.println("PASS "+name);
                }catch(Throwable failure){
                    row.put("pass",false);row.put("failure_class",failure.getClass().getName());row.put("failure",failure.toString());
                    List<String> stack=new ArrayList<String>();for(StackTraceElement frame:failure.getStackTrace())stack.add(frame.toString());
                    row.put("stack",stack);failure.printStackTrace(System.err);System.out.println("FAIL "+name);
                }
                row.put("assertions",assertions-before);results.add(row);
            }
        }finally{
            ObserverPipelineHost.observationIo.executor.shutdown();
        }
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.ctrip-form-sampling-worker-cases.v1");out.put("cases",names.size());out.put("assertions",assertions);
        out.put("case_names",names);out.put("results",results);out.put("passed",passed);out.put("all_pass",passed==names.size());
        out.put("real_worker_to_six_argument_accept",true);
        out.put("android_graph_window_clock_synthetic",true);out.put("existing_session_io_carrier_synthetic",true);
        out.put("actual_session_entered_receipt_proved",false);out.put("phone_operations",0);out.put("action_dispatches",0);
        out.put("worker_case_lineage","r2 48: replace incorrect interactive_variable_child expectation with direct-sibling read-only control plus original nested-click refusal; now 49");
        out.put("current_successor_lineage","Original 49 cases retain assertions; three added cases test the unchanged final history boundary and frozen optional diagnostics.");
        out.put("current_diagnostic_mask_scope","bit4 is the original initial-check result; remaining bits are the actual locked endpoint, not an earlier unlogged cause.");
        out.put("host_json_nullable_decode",Arrays.asList("label","ref_signature_sha256","input_sha256"));
        out.put("decoded_census_requires_original_complete_sha",true);
        out.put("business_completion_verified",false);out.put("defb_missing_pair_reconstructed",false);
        Files.write(Paths.get(args[0]),(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        System.out.println("RESULT cases="+names.size()+" passed="+passed+" assertions="+assertions);
        if(passed!=names.size())System.exit(1);
    }
}
