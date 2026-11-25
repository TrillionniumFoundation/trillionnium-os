package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Actual observer bodies, full node values, and explicit synthetic Android/event/clock ports. */
public final class FormReadPublicationHostTest {
    private static int assertions;
    private static final List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();
    private static void need(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static long number(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Number,"number "+k);return ((Number)v).longValue();}
    @SuppressWarnings("unchecked")
    private static void run(String scenario,boolean published){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("scenario",scenario);
        try{
            Map<String,Object> r=ObserverPipelineHost.exerciseFormScenario(scenario);row.put("result",r);
            need(number(r,"publications")==(published?1:0),"publication "+scenario);
            for(String key:Arrays.asList("original_deadline_preserved","all_graphs_closed","all_bitmaps_recycled","all_buffers_closed","workers_drained","no_action_work"))
                need(Boolean.TRUE.equals(r.get(key)),key);
            need(number(r,"new_full_reads")==4,"only two samples, B and C; no new traversal");
            need(number(r,"diagnostic_json_bytes")<=16384,"original diagnostic cap");
            Map<String,Object> diag=(Map<String,Object>)r.get("diagnostic_snapshot");
            Map<String,Object> decision=(Map<String,Object>)diag.get("last_form_publication_decision");
            if(published){
                need(number(r,"new_png_files")==1,"one new PNG");
                need(number(r,"captured_at")==number(r,"actual_capture_requested_at"),"original capture age");
                Map<String,Object> e=(Map<String,Object>)r.get("capture_evidence");
                need("post_encoding_form_pair_history".equals(e.get("mode")),"historical post-encoding form mode");
                need(Boolean.FALSE.equals(e.get("grants_action_authority"))&&Boolean.FALSE.equals(e.get("business_completion_verified")),"no action/business authority");
                need(Boolean.TRUE.equals(e.get("fresh_action_validation_required")),"new action validation still needed");
                need(Boolean.FALSE.equals(e.get("same_instant_pixels_and_ax_claimed")),"no simultaneous A/C claim");
                need(Boolean.FALSE.equals(e.get("post_encoding_whole_graph_rechecked")),"different C not whole equality");
                need(number(r,"capture_evidence_bytes")<=8192,"original PhoneObservation cap");
                need(number(r,"full_form_artifact_count")==1,"one full proof sidecar");
                Map<String,Object> comparison=(Map<String,Object>)e.get("post_encoding_form_pair_comparison");
                Map<String,Object> artifact=(Map<String,Object>)r.get("full_form_artifact");
                Map<String,Object> full=(Map<String,Object>)artifact.get("post_encoding");
                Map<String,Object> ref=(Map<String,Object>)comparison.get("complete_comparison_artifact");
                need(!comparison.containsKey("entered_open_read_permit"),"ordinary read cannot invent entered OPEN");
                need(Boolean.TRUE.equals(comparison.get("full_census_compared")),"full census comparison");
                need(Boolean.FALSE.equals(comparison.get("changed_paths_truncated")),"all changed paths");
                need(Boolean.FALSE.equals(comparison.get("query_history_proved")),"no query proof");
                need(Boolean.FALSE.equals(comparison.get("grants_action_authority")),"comparison grants no action");
                need(r.get("full_form_artifact_sha256").equals(ref.get("sha256"))&&number(r,"full_form_artifact_bytes")==number(ref,"bytes"),"actual full artifact ref");
                need(number(artifact,"captured_elapsed_ms")==number(r,"captured_at"),"sidecar preserves capture clock");
                need(full.get("literal_form_facts") instanceof Map,"full literal facts retained");
                int count=Integer.getInteger("hepta.form.expected.nodes",0);
                if(count>0)need(number(comparison,"before_visited_nodes")==count&&number(comparison,"after_visited_nodes")==count,"all actual node values");
                int changed=Integer.getInteger("hepta.form.expected.changes",1);
                need(((List<?>)comparison.get("changed_paths")).size()==changed,"every real/synthetic difference classified");
                need(decision!=null&&Boolean.TRUE.equals(decision.get("events_covered"))&&Boolean.TRUE.equals(decision.get("form_comparison_attempted"))
                    &&Boolean.TRUE.equals(decision.get("form_comparison_proved")),"copied C decision");
                need(number(decision,"captured_elapsed_ms")==number(r,"captured_at"),"diagnostic preserves capture clock");
                need(Boolean.FALSE.equals(decision.get("grants_publication"))&&Boolean.FALSE.equals(decision.get("grants_action_authority")),"diagnostic grants nothing");
                Map<String,Object> original=(Map<String,Object>)r.get("diagnostic_original");
                Map<String,Object> copied=(Map<String,Object>)original.get("last_form_publication_decision");
                boolean immutable=false;try{copied.put("events_covered",false);}catch(UnsupportedOperationException expected){immutable=true;}
                need(immutable,"immutable decision map");
                immutable=false;try{((List<Object>)copied.get("capture_watermark")).set(0,Long.valueOf(999));}catch(UnsupportedOperationException expected){immutable=true;}
                need(immutable,"immutable copied counters");
            }else{
                need(number(r,"new_png_files")==0,"unpublished frame deleted");
                need(Boolean.TRUE.equals(r.get("original_observation_retained")),"old frame retained, no stale replacement");
                if(scenario.equals("read_late_boundary")||scenario.equals("read_late_unknown"))
                    need(decision!=null&&Boolean.FALSE.equals(decision.get("events_covered"))&&Boolean.FALSE.equals(decision.get("form_comparison_attempted")),"independent event boundary refuses comparator");
                if(scenario.equals("read_late_late_boundary")||scenario.equals("read_late_sidecar_content")||scenario.equals("read_late_main_handoff"))
                    need(decision!=null&&Boolean.TRUE.equals(decision.get("form_comparison_proved")),"late event refuses even after valid C classification");
            }
            row.put("passed",true);System.out.println("PASS "+scenario);
        }catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());System.out.println("FAIL "+scenario+" "+failure);}
        records.add(row);
    }
    @SuppressWarnings("unchecked")
    private static void enteredOpen(){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("scenario","existing_entered_open_post_encoding_retained");
        try{
            Map<String,Object> r=ObserverPipelineHost.exerciseFormScenario("post_late_classified");row.put("result",r);
            need(number(r,"publications")==1,"existing entered OPEN publication");
            need(number(r,"captured_at")==number(r,"actual_capture_requested_at"),"entered OPEN keeps capture time");
            need(Boolean.TRUE.equals(r.get("original_deadline_preserved")),"entered OPEN keeps deadline");
            Map<String,Object> e=(Map<String,Object>)r.get("capture_evidence");
            need("post_encoding_form_pair_history".equals(e.get("mode")),"existing entered OPEN historical mode");
            need(Boolean.FALSE.equals(e.get("grants_action_authority")),"entered history gives no action authority");
            Map<String,Object> artifact=(Map<String,Object>)r.get("full_form_artifact");
            Map<String,Object> full=(Map<String,Object>)artifact.get("post_encoding");
            need(full.get("entered_open_read_permit") instanceof Map,"real entered permit path preserved");
            row.put("passed",true);System.out.println("PASS existing_entered_open_post_encoding_retained");
        }catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());System.out.println("FAIL entered "+failure);}
        records.add(row);
    }
    @SuppressWarnings("unchecked")
    private static void diagnostics(){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("scenario","bounded_latest_diagnostic_copy_and_terminal");
        try{
            ObservationDiagnostics d=new ObservationDiagnostics(NativeActionSnapshotCheckHostTest.ID,NativeActionSnapshotCheckHostTest.repeat('b',32),
                NativeActionSnapshotCheckHostTest.H,NativeAppGoal.CTRIP_PACKAGE,NativeActionSnapshotCheckHostTest.UUID,15,1,1000,13000);
            java.lang.reflect.Method m=ObservationDiagnostics.class.getDeclaredMethod("formPublicationDecision",long.class,long.class,long.class,
                long[].class,long[].class,long[].class,long[].class,boolean.class,boolean.class,boolean.class,boolean.class);
            long[] a={3,0,2,1},b={4,0,3,1};
            m.invoke(d,1100L,1200L,1300L,a,a,b,b,false,true,true,true);
            a[0]=900;b[0]=901;
            Map<String,Object> first=(Map<String,Object>)d.snapshot(1400).get("last_form_publication_decision");
            need(((List<Number>)first.get("capture_watermark")).get(0).longValue()==3,"input array not retained");
            need(((List<Number>)first.get("post_encoding_complete_watermark")).get(0).longValue()==4,"C array copied");
            long[] large={Long.MAX_VALUE,0,Long.MAX_VALUE,0};
            m.invoke(d,2100L,2200L,2300L,large,large,large,large,false,false,false,false);
            Map<String,Object> latest=(Map<String,Object>)d.snapshot(2400).get("last_form_publication_decision");
            need(number(latest,"captured_elapsed_ms")==2100,"latest overwrites prior, no list");
            need(new org.json.JSONObject(latest).toString().getBytes(StandardCharsets.UTF_8).length<2048,"fixed bounded summary");
            d.finish("failed",2500);
            m.invoke(d,3100L,3200L,3300L,large,large,large,large,true,true,false,false);
            need(latest.equals(d.snapshot(3400).get("last_form_publication_decision")),"terminal immutable");
            need(ObservationDiagnostics.MAX_JSON_BYTES==16384&&ObservationDiagnostics.MAX_PRIVATE_JSON_BYTES==2097152,"caps unchanged");
            row.put("passed",true);System.out.println("PASS bounded_latest_diagnostic_copy_and_terminal");
        }catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());System.out.println("FAIL diagnostic "+failure);}
        records.add(row);
    }
    public static void main(String[] args)throws Exception{
        for(String name:Arrays.asList("read_late_success","read_late_during_content","read_late_main_event"))run(name,true);
        for(String name:Arrays.asList("read_late_boundary","read_late_unknown","read_late_late_content","read_late_late_boundary",
            "read_late_date","read_late_overlap","read_late_omission","read_late_owner","read_late_window","read_late_display",
            "read_late_user","read_late_read_before","read_late_cancel","read_late_deadline","read_late_sidecar_content","read_late_main_handoff"))run(name,false);
        if(System.getProperty("hepta.form.raw.census")==null)enteredOpen();
        diagnostics();
        int failed=0;for(Map<String,Object> r:records)if(!Boolean.TRUE.equals(r.get("passed")))failed++;
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.ctrip-form-read-publication-cases.v1");
        out.put("all_pass",failed==0);out.put("cases",records.size());out.put("failed_cases",failed);out.put("assertions",assertions);
        out.put("records",records);out.put("phone_operations",0);out.put("synthetic_android_and_time_ports",true);
        out.put("historical_watermarks_reconstructed",false);out.put("business_completion_verified",false);
        out.put("existing_entered_open_public_fixture_executed",System.getProperty("hepta.form.raw.census")==null);
        Files.write(Paths.get(args[0]),(new org.json.JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("RESULT cases="+records.size()+" assertions="+assertions+" failed="+failed);
        if(failed!=0)System.exit(1);
    }
}
