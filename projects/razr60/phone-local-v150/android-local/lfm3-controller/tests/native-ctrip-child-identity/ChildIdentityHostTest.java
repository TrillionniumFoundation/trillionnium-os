package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
/** Actual Service methods; private original nodes with explicitly synthetic Android IO, clocks, events and owner. */
public final class ChildIdentityHostTest {
    private static int assertions;
    private static final List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();
    private static void require(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static long number(Map<String,Object> m,String k){Object v=m.get(k);require(v instanceof Number,"number "+k);return ((Number)v).longValue();}
    private static void yes(Map<String,Object> m,String k,String s){require(Boolean.TRUE.equals(m.get(k)),s+": "+k+" "+m);}
    private static void no(Map<String,Object> m,String k,String s){require(Boolean.FALSE.equals(m.get(k)),s+": "+k+" "+m);}
    private static void base(String s)throws Exception{
        Map<String,Object> m=ObserverPipelineHost.exerciseOriginalChildNote(s);
        yes(m,"sticky",s);yes(m,"no_reads",s);require(number(m,"typed_failures")==1&&number(m,"capture_failures")==1,s+" counters preserved");records.add(m);
    }
    @SuppressWarnings("unchecked")
    private static void direct(String s)throws Exception{
        Map<String,Object> m=ObserverPipelineHost.exerciseChildIdentity(s);
        boolean positive=Arrays.asList("same_identity","known_content_before_read","known_content_during_read").contains(s);
        require(Boolean.valueOf(!positive).equals(m.get("sticky")),s+": latch outcome "+m);
        for(String key:Arrays.asList("deadline_unchanged","no_publication_or_effect","native_278_kept","diagnostic_frozen",
                "all_graphs_closed","all_bitmaps_recycled","workers_drained"))yes(m,key,s);
        require(number(m,"body_reads")==0,s+": identity read is never full body authorization");
        require(number(m,"identity_reads")<=1,s+": at most one full identity endpoint");
        boolean second="second_stale_is_not_reopened".equals(s);
        require(number(m,"typed_failures")==("untyped_failure".equals(s)?0:second?2:1),s+": typed failure accounting");
        require(number(m,"capture_failures")==(second?2:1),s+": failed capture remains counted");
        if(positive){
            yes(m,"proof_returned",s);require(number(m,"identity_reads")==1,s+": actual identity endpoint executed");
            Map<String,Object> d=(Map<String,Object>)m.get("diagnostic");
            require(d!=null&&Boolean.TRUE.equals(d.get("same_identity_at_note")),s+": consumed complete fresh identity");
            require(((Number)d.get("read_completed_elapsed_ms")).longValue()-((Number)d.get("read_started_elapsed_ms")).longValue()==7,s+": IO time charged");
            require(d.containsKey("task_deadline_elapsed_ms"),s+": original task deadline recorded");
        }
        if(second){yes(m,"second_proof_absent",s);yes(m,"first_read_and_note_preserved",s);no(m,"sticky_after_first",s);}
        records.add(m);
    }
    @SuppressWarnings("unchecked")
    private static void pipeline(String s)throws Exception{
        Map<String,Object> m=ObserverPipelineHost.exerciseChildPipeline(s);
        for(String key:Arrays.asList("failed_pixels_discarded","first_attempt_published_nothing","deadline_unchanged",
                "no_action_or_business_completion","all_graphs_closed","all_bitmaps_recycled","all_buffers_closed","workers_drained"))yes(m,key,s);
        require(number(m,"typed_failures")==1,s+": failed capture typed counter remains");
        if(s.equals("pipeline_complete_resample")){
            no(m,"first_sticky",s);require(number(m,"publications")==1&&number(m,"new_png_files")==1,s+": one wholly new publication "+m);
            require(number(m,"full_reads")>=10,s+": original frame, failed pair, new complete A/B/C all read");
            yes(m,"capture_time_preserved",s);yes(m,"new_frame",s);
            Map<String,Object> e=(Map<String,Object>)m.get("capture_evidence");
            require("post_encoding_form_pair_history".equals(e.get("mode")),s+": original strict form classifier");
            require(Boolean.FALSE.equals(e.get("grants_action_authority"))&&Boolean.FALSE.equals(e.get("business_completion_verified"))
                    &&Boolean.TRUE.equals(e.get("fresh_action_validation_required")),s+": no action or completion authority");
            require(number(m,"history_artifacts")==1,s+": complete original classifier artifact");
        }else{
            yes(m,"first_sticky",s);require(number(m,"publications")==0&&number(m,"new_png_files")==0,s+": unknown event cannot publish");
        }
        records.add(m);
    }
    public static void main(String[] args)throws Exception{
        boolean baseline=args.length>1&&"baseline".equals(args[1]);
        if(baseline){base("typed_stale");base("already_sticky");}
        else{
            for(String s:Arrays.asList("same_identity","known_content_before_read","known_content_during_read","untyped_failure","noncanonical_path","root_path","incomplete_capture","missing_native_census","capture_replaced","generation_replaced","existing_sticky","initial_scope","native_ax_scope","mixed_ordinary_identity","unsupported_target","unknown_before_read","boundary_before_read","untyped_before_read","window_census_mismatch","window_id_mismatch","window_metadata_mismatch","profile_token_mismatch","unknown_during_read","boundary_during_read","untyped_during_read","deadline_during_read","cancel_during_read","owner_retired_during_read","authorization_replaced_during_read","task_lease_retired_during_read","identity_reader_throws","content_before_note","unknown_before_note","token_before_note","cancel_before_note","deadline_before_note","task_deadline_before_note","transition_deadline_before_note","second_stale_is_not_reopened"))direct(s);
            for(String s:Arrays.asList("pipeline_complete_resample","pipeline_unknown_identity_read"))pipeline(s);
        }
        List<String> names=new ArrayList<String>();for(Map<String,Object> r:records)names.add((String)r.get("scenario"));
        require(new HashSet<String>(names).size()==names.size(),"unique declared cases");
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("all_pass",true);result.put("cases",records.size());
        result.put("assertions",assertions);result.put("case_names",names);result.put("results",records);
        result.put("android_io_events_clock_owner_synthetic",true);result.put("private_original_nodes_preserved",true);
        result.put("actual_historical_exception_type_known",false);result.put("phone_operations",0);
        Files.write(Paths.get(args[0]),(new org.json.JSONObject(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(new org.json.JSONObject(result).toString());
    }
}
