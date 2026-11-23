package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual tracker and actual Service serializers, with explicit already-read host
 * AX values and clocks. This does not run an Android observer or grant authority. */
final class AxPublicationDiagnosticsHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private interface Case {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Case body)throws Exception{
        check(!names.contains(name),"unique case identity");body.run();names.add(name);System.out.println("PASS "+name);
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> map(Object value){return (Map<String,Object>)value;}
    @SuppressWarnings("unchecked")
    private static List<Map<String,Object>> rows(Object value){return (List<Map<String,Object>>)value;}
    private static Map<String,Object> values(Object... pairs){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;
    }
    private static Map<String,Object> watermark(long events,long content,long boundary,long unknown){
        return values("events",events,"unknown",unknown,"content",content,"boundary",boundary);
    }
    private static Map<String,Object> census(int count,long begin,long end){
        Map<String,Object> identity=values("task_id",DiagnosticChecks.TASK,"owner_sha256",DiagnosticChecks.OWNER,
            "execution_target_sha256",DiagnosticChecks.OWNER,"task_authorization_sha256",DiagnosticChecks.OWNER,
            "actual_selection_sha256",DiagnosticChecks.OWNER,"native_goal_sha256",DiagnosticChecks.OWNER,
            "package",DiagnosticChecks.APP,"background_generation",DiagnosticChecks.GENERATION,
            "app_tree_sha256",DiagnosticChecks.OWNER,"observation_state_sha256",DiagnosticChecks.OWNER,
            "display_id",9,"window_id",71,"rotation",0,"width",1080,"height",2400,
            "left",0,"top",0,"right",1080,"bottom",2400);
        Map<String,Object> window=values("metadata","actual host window metadata","package",DiagnosticChecks.APP,
            "window_id",71,"display_id",9,"rotation",0,"left",0,"top",0,"right",1080,"bottom",2400,"width",1080,"height",2400);
        List<Map<String,Object>> nodes=new ArrayList<Map<String,Object>>();
        for(int i=0;i<count;i++){
            Map<String,Object> n=DiagnosticGraphHost.node(i==0?"0":"0/"+(i-1),i==0?count-1:0);
            if(count>100){n.put("text","");n.put("description","");n.put("label",null);}
            nodes.add(n);
        }
        return values("identity",identity,"complete",true,"truncated",false,"read_started_elapsed_ms",begin,
            "read_completed_elapsed_ms",end,"census_captured_elapsed_ms",begin+1,
            "visited",count,"retained",Math.min(count,2),"pending",0,"child_slots_omitted",0L,
            "node_budget_omissions",0,"text_budget_omissions",0,
            "reported_windows",values("windows",Arrays.asList(values("window_id",71,"display_id",9,
                "package",DiagnosticChecks.APP,"bounds",Arrays.asList(0,0,1080,2400)))),
            "window",window,"profile_window",null,"profile_owner",null,"nodes",nodes);
    }
    private static void profile(Map<String,Object> c,int leaf,String proof){
        Map<String,Object> owner=DiagnosticGraphHost.profile(leaf,"22222222-2222-2222-2222-222222222222");
        c.put("profile_owner",owner);c.put("profile_window",values(
            "target_identity_sha256",owner.get("profile_target_sha256"),"user_id",owner.get("profile_user_id"),
            "user_serial",owner.get("profile_user_serial"),"full_uid",owner.get("profile_full_uid"),
            "task_id",owner.get("profile_task_id"),"parent_task_id",owner.get("profile_parent_task_id"),
            "task_token_id",owner.get("profile_task_token_id"),"proof_id",proof));
    }
    private static Map<String,Object> facts(){
        List<Map<String,Object>> history=new ArrayList<Map<String,Object>>();
        history.add(values("stage","ax_before_transfer","reason","late_content","checked_elapsed_ms",1570L,
            "watermark",watermark(13,13,0,0)));
        return values("reason_codes",new ArrayList<String>(Arrays.asList("late_content")),"rejections",history,
            "capture_watermark",watermark(10,10,0,0),"completed_watermark",watermark(12,12,0,0),
            "current_watermark",watermark(13,13,0,0),"window_checked",true,"window_matched",true,
            "captured_elapsed_ms",1200L,"complete_endpoint_elapsed_ms",1410L,"sealed_elapsed_ms",1420L,
            "persisted_elapsed_ms",1500L,"window_started_elapsed_ms",1510L,"window_completed_elapsed_ms",1550L,
            "publication_recheck_count",0,"receipt_sha256",DiagnosticChecks.repeat('b',64),"previous_pair",null,
            "first_ime_visibility","hidden","second_ime_visibility","hidden");
    }
    private static ObservationDiagnostics record(Map<String,Object> a,Map<String,Object> b,Map<String,Object> f){
        ObservationDiagnostics d=DiagnosticGraphHost.tracker();d.axPublicationRejected("ax_before_transfer",a,b,f,1600);return d;
    }
    private static JSONObject privateWire(ObservationDiagnostics d)throws Exception{
        String raw=ObserverPipelineHost.actualPrivateSnapshot(d).call();JSONObject out=new JSONObject(raw);
        check(raw.getBytes(StandardCharsets.UTF_8).length<=2097152&&out.toString(2).getBytes(StandardCharsets.UTF_8).length<=2097152,"real compact and pretty private UTF8 cap");
        check(!out.getBoolean("grants_action_authority")&&!out.getBoolean("grants_publication")
            &&!out.getBoolean("business_verified")&&!out.getBoolean("sent_to_model"),"private diagnostics grant no authority");
        check(out.getInt("additional_node_samples")==0&&out.getInt("additional_screenshots")==0
            &&!out.getBoolean("changes_deadline")&&out.getLong("deadline_elapsed_ms")==13000,"diagnostic adds no sampling or time");
        return out;
    }
    private static JSONObject compact(ObservationDiagnostics d)throws Exception{
        String raw=ObserverPipelineHost.actualSnapshot(d).call();JSONObject out=new JSONObject(raw);
        check(raw.getBytes(StandardCharsets.UTF_8).length<=16384&&out.toString(2).getBytes(StandardCharsets.UTF_8).length<=16384,"original 16KiB compact and pretty bound");
        check(!raw.contains("PRIVATE_BODY_NOT_FOR_DIAGNOSTIC")&&!raw.contains("AX_PRIVATE_UNICODE"),"compact channel never contains node text");
        return out;
    }
    private static JSONObject failed(ObservationDiagnostics d)throws Exception{d.finish("failed",1900);return privateWire(d);}
    private static void noPair(JSONObject out){
        check(!out.getBoolean("complete_pair_recorded")&&out.getInt("raw_pair_count")==0&&!out.getBoolean("node_text_recorded"),"no incomplete or foreign complete claim");
        check(!out.has("before")&&!out.has("after"),"no partial private node bodies");
    }
    private static JSONObject last(ObservationDiagnostics d)throws Exception{return compact(d).getJSONObject("last_ax_publication_rejection");}

    public static void main(String[] args)throws Exception{
        test("equal_completed_AX_pair_survives_only_as_failed_private_evidence",()->{
            Map<String,Object> a=census(280,1010,1100),b=census(280,1300,1400);
            rows(a.get("nodes")).get(279).put("text","AX_PRIVATE_UNICODE_末项");
            rows(b.get("nodes")).get(279).put("text","AX_PRIVATE_UNICODE_末项");
            ObservationDiagnostics d=record(a,b,facts());JSONObject out=failed(d);
            check(out.getBoolean("complete_pair_recorded")&&out.getInt("raw_pair_count")==1,"one full pair retained");
            check(out.getString("status").equals("complete_equal_pair_publication_rejected"),"equal pair has distinct refusal status");
            check(out.getLong("full_graph_change_count")==0&&!compact(d).has("native_full_graph_change_count"),"no fabricated full-graph-change event");
            check(out.getString("selected_pair_ordinal_kind").equals("ax_publication_rejection"),"ordinal namespace explicit");
            check(out.getJSONObject("before").getJSONArray("native_nodes").length()==280&&out.getJSONObject("after").getJSONArray("native_nodes").length()==280,"all native nodes preserved");
            check(out.toString().contains("AX_PRIVATE_UNICODE_末项"),"private last-node Unicode remains exact");
            check(out.getJSONObject("selected_pair_publication_rejection").getJSONObject("facts").getJSONObject("current_watermark").getLong("events")==13,"actual refusal watermark");
            check(!out.getBoolean("worker_drained_proved_by_this_record"),"diagnostic is not cleanup proof");
        });
        test("running_and_published_requests_never_export_raw_pair",()->{
            ObservationDiagnostics d=record(census(3,1010,1100),census(3,1300,1400),facts());
            JSONObject running=privateWire(d);noPair(running);check(running.getString("status").equals("request_not_terminal"),"running status honest");
            d.published("44444444444444444444444444444444",1700);JSONObject done=privateWire(d);noPair(done);
            check(done.getString("status").equals("request_published")&&!done.has("selected_pair_publication_rejection"),"publication releases raw pair and private facts");
        });
        test("terminal_refusal_cannot_be_changed_by_late_worker_or_caller",()->{
            ObservationDiagnostics d=record(census(3,1010,1100),census(3,1300,1400),facts());String before=failed(d).toString();
            d.axPublicationRejected("ax_before_transfer",census(4,2010,2100),census(4,2300,2400),facts(),2500);
            d.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_PASSED);d.phase("ax_publication_graph_recheck",2600);
            check(privateWire(d).toString().equals(before),"terminal byte-equivalent snapshot frozen");
            JSONObject returned=privateWire(d);returned.getJSONObject("after").getJSONArray("native_nodes").getJSONObject(0).put("text","CALLER_MUTATION");
            check(privateWire(d).toString().equals(before),"returned JSON cannot mutate trace");
        });
        test("copied_raw_nodes_windows_and_refusal_facts_are_deeply_frozen",()->{
            Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400),f=facts();
            ObservationDiagnostics d=record(a,b,f);String before=failed(d).toString();
            rows(a.get("nodes")).clear();rows(b.get("nodes")).get(0).put("text","MUTATED");
            map(a.get("reported_windows")).clear();map(f.get("current_watermark")).clear();rows(f.get("rejections")).clear();
            check(privateWire(d).toString().equals(before),"all original aliases detached");
        });
        test("recheck_pair_keeps_original_A_clock_and_separate_original_B_proof",()->{
            Map<String,Object> f=facts();f.put("publication_recheck_count",1);
            f.put("complete_endpoint_elapsed_ms",1710L);f.put("sealed_elapsed_ms",1720L);f.put("persisted_elapsed_ms",1800L);
            f.put("window_started_elapsed_ms",1810L);f.put("window_completed_elapsed_ms",1850L);
            f.put("completed_watermark",watermark(14,14,0,0));f.put("current_watermark",watermark(15,15,0,0));
            f.put("previous_pair",values("pair_graph_started_elapsed_ms",1300L,"pair_graph_completed_elapsed_ms",1400L,
                "complete_endpoint_elapsed_ms",1410L,"pair_sealed_elapsed_ms",1420L,"receipt_persisted_and_hashed_elapsed_ms",1500L,
                "publication_check_started_elapsed_ms",1510L,"publication_check_completed_elapsed_ms",1550L,
                "captured_elapsed_ms",1200L,"completed_watermark",watermark(12,12,0,0),
                "receipt_sha256",DiagnosticChecks.repeat('c',64),"recheck_admitted_elapsed_ms",1600L,
                "recheck_admission_watermark",watermark(13,13,0,0),"reason","late_typed_content"));
            ObservationDiagnostics d=DiagnosticGraphHost.tracker();
            d.axPublicationRejected("ax_before_transfer",census(3,1010,1100),census(3,1620,1700),f,1900);
            JSONObject out=failed(d),saved=out.getJSONObject("selected_pair_publication_rejection").getJSONObject("facts");
            check(out.getBoolean("complete_pair_recorded")&&saved.getLong("captured_elapsed_ms")==1200,"original capture is not refreshed");
            check(out.getJSONObject("before").getJSONObject("read").getLong("read_completed_elapsed_ms")==1100
                &&out.getJSONObject("after").getJSONObject("read").getLong("read_completed_elapsed_ms")==1700,"true A and C read intervals");
            check(saved.getJSONObject("previous_pair").getLong("pair_graph_completed_elapsed_ms")==1400
                &&saved.getJSONObject("previous_pair").getString("receipt_sha256").equals(DiagnosticChecks.repeat('c',64)),"old B receipt remains separate");
            check(saved.getJSONObject("completed_watermark").getLong("events")==14&&saved.getInt("publication_recheck_count")==1,"final C endpoint and one-shot count");
        });
        test("profile_ephemeral_proofs_do_not_replace_stable_owner_identity",()->{
            Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400);profile(a,501,"first proof");profile(b,501,"second proof");
            JSONObject out=failed(record(a,b,facts()));
            check(out.getString("status").equals("complete_equal_pair_publication_rejected"),"stable profile pair remains equal");
            JSONObject id=out.getJSONObject("after").getJSONObject("identity");
            check(id.getInt("profile_user_id")==10&&id.getInt("profile_full_uid")==1010485&&id.getInt("profile_task_id")==501,"real full UID and profile task retained");
        });
        test("foreign_pair_identity_cannot_replace_previously_bound_pair",()->{
            for(String key:Arrays.asList("task_id","owner_sha256","package","background_generation","display_id","native_goal_sha256")){
                Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400);
                ObservationDiagnostics d=record(a,b,facts());Map<String,Object> foreign=census(3,1300,1400);
                Object value=key.equals("task_id")?DiagnosticChecks.repeat('9',32):key.equals("package")?"foreign.app":
                    key.equals("background_generation")?"99999999-2222-3333-4444-555555555555":key.equals("display_id")?Integer.valueOf(10):DiagnosticChecks.repeat('d',64);
                map(foreign.get("identity")).put(key,value);if(map(foreign.get("window")).containsKey(key))map(foreign.get("window")).put(key,value);
                if(key.equals("package"))for(Map<String,Object> row:rows(foreign.get("nodes")))row.put(key,value);
                d.axPublicationRejected("ax_before_transfer",a,foreign,facts(),1650);JSONObject out=failed(d);
                check(out.getLong("selected_pair_ordinal")==1&&out.getLong("ax_publication_rejection_count")==2,"foreign record cannot replace valid pair: "+key);
                check(!out.getJSONObject("after").getJSONObject("identity").toString().contains("foreign.app"),"bound original nodes remain");
            }
        });
        test("profile_UID_or_leaf_drift_is_never_an_equal_pair",()->{
            for(boolean mismatch:new boolean[]{false,true}){
                Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400);profile(a,501,"a");profile(b,mismatch?502:501,"b");
                if(!mismatch)map(b.get("profile_window")).put("full_uid",1010999);
                ObservationDiagnostics d=record(a,b,facts());noPair(failed(d));
                check(!last(d).optBoolean("pair_equal",false),"profile proof mismatch not equal");
            }
        });
        test("missing_partial_omitted_or_malformed_census_never_becomes_complete",()->{
            for(int mode=0;mode<10;mode++){
                Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400);
                switch(mode){case 0:b=null;break;case 1:b.put("complete",false);break;case 2:b.put("truncated",true);break;
                    case 3:b.put("pending",1);break;case 4:b.put("child_slots_omitted",1L);break;
                    case 5:b.put("node_budget_omissions",1);break;case 6:b.put("text_budget_omissions",1);break;
                    case 7:rows(b.get("nodes")).remove(2);b.put("visited",2);break;
                    case 8:rows(b.get("nodes")).get(2).put("parent_class","wrong.Parent");break;
                    default:b.remove("reported_windows");}
                noPair(failed(record(a,b,facts())));
            }
        });
        test("unobserved_visible_or_unknown_IME_is_not_invented_as_hidden",()->{
            for(Object ime:new Object[]{null,"visible","unknown"}){
                Map<String,Object> f=facts();f.put("second_ime_visibility",ime);ObservationDiagnostics d=record(census(3,1010,1100),census(3,1300,1400),f);
                noPair(failed(d));check(last(d).getString("status").equals("complete_pair_context_unavailable"),"explicit IME context refusal");
            }
        });
        test("actual_read_intervals_must_be_completed_ordered_and_within_request",()->{
            for(int mode=0;mode<5;mode++){
                Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400);
                switch(mode){case 0:a.put("read_started_elapsed_ms",999L);a.put("census_captured_elapsed_ms",1000L);break;
                    case 1:b.put("read_completed_elapsed_ms",1700L);break;case 2:b.put("read_completed_elapsed_ms",1200L);break;
                    case 3:b.put("read_started_elapsed_ms",1090L);b.put("census_captured_elapsed_ms",1091L);break;
                    default:b.put("census_captured_elapsed_ms",1450L);}
                noPair(failed(record(a,b,facts())));
            }
        });
        test("changed_nodes_and_reported_windows_remain_different_not_equal",()->{
            for(int mode=0;mode<3;mode++){
                Map<String,Object> a=census(3,1010,1100),b=census(3,1300,1400);
                if(mode==0)rows(b.get("nodes")).get(1).put("text","ACTUAL_CHANGED_TEXT");
                else if(mode==1)map(b.get("window")).put("metadata","changed window metadata");
                else map(b.get("reported_windows")).put("additional_observed_window",true);
                JSONObject out=failed(record(a,b,facts()));
                check(out.getBoolean("complete_pair_recorded")&&out.getString("status").equals("complete_difference_pair_publication_rejected"),"completed changed pair distinguished");
                check(!out.getJSONObject("selected_pair_publication_rejection").getBoolean("pair_equal")&&out.getLong("full_graph_change_count")==0,"no equal or fabricated graph-change count");
            }
        });
        test("old_full_graph_difference_counter_and_pair_selection_remain_independent",()->{
            ObservationDiagnostics d=record(census(3,1010,1100),census(3,1300,1400),facts());
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);
            DiagnosticGraphHost.change(b,1,"text","ORIGINAL_GRAPH_DIFFERENCE");
            d.fullGraphChange("ax_publication_graph_recheck",DiagnosticGraphHost.fullStamp(a),DiagnosticGraphHost.fullStamp(b),1700);
            JSONObject out=failed(d);check(out.getLong("full_graph_change_count")==1&&out.getLong("ax_publication_rejection_count")==1,"two counters have original meanings");
            check(out.getString("status").equals("complete_difference_pair")&&!out.has("selected_pair_ordinal_kind")&&!out.has("selected_pair_publication_rejection"),"later actual difference replaces selected pair without stale metadata");
        });
        test("invalid_refusal_shapes_vocabulary_clocks_and_watermarks_are_explicit",()->{
            for(int mode=0;mode<14;mode++){
                Map<String,Object> f=facts();
                switch(mode){case 0:f.put("arbitrary_private_text","must not retain");break;case 1:f.remove("receipt_sha256");break;
                    case 2:f.put("reason_codes",Arrays.asList("not_a_reason"));break;case 3:f.put("reason_codes",Arrays.asList("late_content","late_content"));break;
                    case 4:f.put("reason_codes",new ArrayList<String>());break;case 5:f.put("publication_recheck_count",2);break;
                    case 6:f.put("persisted_elapsed_ms",1700L);break;case 7:f.put("captured_elapsed_ms",-1L);break;
                    case 8:f.put("current_watermark",null);break;case 9:f.put("current_watermark",watermark(1,2,0,0));break;
                    case 10:f.put("window_checked",false);break;case 11:f.put("receipt_sha256","not-sha");break;
                    case 12:f.put("first_ime_visibility","unbounded arbitrary input");break;default:f.put("previous_pair",values("reason","late_typed_content"));}
                ObservationDiagnostics d=record(census(3,1010,1100),census(3,1300,1400),f);noPair(failed(d));
                check(last(d).getString("status").equals("invalid_rejection_facts")&&!last(d).getBoolean("rejection_facts_valid"),"invalid facts explicit: "+mode);
            }
        });
        test("history_bound_and_arbitrary_stage_cannot_create_private_evidence",()->{
            Map<String,Object> f=facts();List<Map<String,Object>> history=rows(f.get("rejections"));
            Map<String,Object> row=history.get(0);for(int i=1;i<7;i++)history.add(row);
            ObservationDiagnostics d=record(census(3,1010,1100),census(3,1300,1400),f);noPair(failed(d));
            check(last(d).getString("status").equals("invalid_rejection_facts"),"seven histories refused");
            d=DiagnosticGraphHost.tracker();d.axPublicationRejected("arbitrary_stage",census(3,1010,1100),census(3,1300,1400),facts(),1600);
            check(!compact(d).has("last_ax_publication_rejection"),"unknown stage does not enter tracker");noPair(failed(d));
        });
        test("missing_optional_capture_steps_are_preserved_as_unobserved",()->{
            Map<String,Object> f=facts();f.put("receipt_sha256",null);f.put("completed_watermark",null);
            f.put("complete_endpoint_elapsed_ms",-1L);f.put("sealed_elapsed_ms",-1L);f.put("persisted_elapsed_ms",-1L);
            f.put("window_started_elapsed_ms",-1L);f.put("window_completed_elapsed_ms",-1L);f.put("window_checked",false);f.put("window_matched",false);
            ObservationDiagnostics d=record(null,null,f);JSONObject out=failed(d);noPair(out);
            JSONObject note=last(d);check(note.getBoolean("rejection_facts_valid")&&note.isNull("receipt_sha256")&&note.isNull("completed_watermark"),"missing receipt is not a fabricated hash or watermark");
            check(note.getLong("persisted_elapsed_ms")==-1&&!note.getBoolean("window_checked"),"unobserved step times explicit");
        });
        test("private_capacity_refusal_never_truncates_and_labels_pair_complete",()->{
            Map<String,Object> a=census(300,1010,1100),b=census(300,1300,1400);
            for(Map<String,Object> row:rows(a.get("nodes")))row.put("label",DiagnosticChecks.repeat('界',4096));
            for(Map<String,Object> row:rows(b.get("nodes")))row.put("label",DiagnosticChecks.repeat('界',4096));
            JSONObject out=failed(record(a,b,facts()));noPair(out);
            check(out.getString("status").equals("complete_pair_value_budget_exceeded")&&out.getBoolean("raw_pair_omitted_for_budget"),"budget refusal explicit");
            check(out.getJSONObject("before_summary").getInt("full_native_nodes")==300&&!out.toString().contains(DiagnosticChecks.repeat('界',30)),"complete counts survive without a raw prefix");
        });
        test("new_phase_and_event_names_remain_bounded_diagnostic_values",()->{
            ObservationDiagnostics d=DiagnosticGraphHost.tracker();d.phase("ax_publication_graph_recheck",1200);
            d.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_STARTED);d.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_PASSED);
            d.note(ObservationDiagnostics.Event.AX_PUBLICATION_RECHECK_REJECTED);d.finish("failed",1300);
            JSONObject out=compact(d);check(out.getJSONObject("events").getLong("AX_PUBLICATION_RECHECK_STARTED")==1
                &&out.getJSONObject("events").getLong("AX_PUBLICATION_RECHECK_PASSED")==1
                &&out.getJSONObject("events").getLong("AX_PUBLICATION_RECHECK_REJECTED")==1,"typed events accepted");
            check(out.getJSONObject("phases").getJSONObject("ax_publication_graph_recheck").getLong("total_ms")==100
                &&out.getLong("deadline_elapsed_ms")==13000&&!out.getBoolean("changes_deadline"),"phase measures time without changing budget");
        });
        JSONObject report=new JSONObject().put("schema","hepta.ax-publication-diagnostics-host.v1").put("all_pass",true)
            .put("cases",names.size()).put("assertions",assertions).put("case_names",names)
            .put("actual_tracker_and_Service_serializers",true).put("deadline_or_sampling_changed",false)
            .put("android_execution",false).put("phone_operations",0).put("business_completion_verified",false);
        Files.write(Paths.get(args[0]),report.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
