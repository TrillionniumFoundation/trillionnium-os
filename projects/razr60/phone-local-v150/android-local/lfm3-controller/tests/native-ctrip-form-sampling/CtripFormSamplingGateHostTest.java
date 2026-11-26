
package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;

/** Actual Gate timing/state machine only. These FrameKeys are explicit host values;
 * complete form classification and Android graph authority are tested separately. */
public final class CtripFormSamplingGateHostTest {
    private static int assertions;
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    interface Body {void run()throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void one(String name,Body body){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{body.run();row.put("passed",true);}catch(Throwable failure){
            row.put("passed",false);row.put("failure_class",failure.getClass().getName());row.put("failure",failure.getMessage());
        }results.add(row);
    }
    private static ObservationStabilityGate.FrameKey key(String digest){
        return new ObservationStabilityGate.FrameKey("ctrip.android.view",96,0,0,0,1224,2992,digest,false);
    }
    private static ObservationStabilityGate gate(){
        return new ObservationStabilityGate(1000,ObservationStabilityGate.requestDeadline(1000,20000));
    }
    private static void initial(ObservationStabilityGate g,ObservationStabilityGate.FrameKey a){
        check(g.sample(1000,a,true)==ObservationStabilityGate.Result.WAIT,"actual first sample initializes its real key and timestamp");
    }
    public static void main(String[] args)throws Exception{
        one("classified_gate_199ms_wait_200ms_ready_for_two_unchanged_real_keys",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(!a.equals(b),"the actual whole graph keys differ");
            check(g.sampleClassifiedPair(1199,a,1000,b,true)==ObservationStabilityGate.Result.WAIT,"199ms does not satisfy original sample gap");
            check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.READY,"200ms accepts explicitly classified values");
            check("whole-before".equals(a.observedDigest)&&"whole-after".equals(b.observedDigest),"neither key digest is rewritten");
            check(g.sample(1399,b,true)==ObservationStabilityGate.Result.WAIT,"accepted evidence now owns the real second key and time");
            check(g.sample(1400,b,true)==ObservationStabilityGate.Result.READY,"ordinary sampling sees the actual second key");
        });
        one("classified_gate_original_sample_still_requires_whole_key_equality",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(g.sample(1200,b,true)==ObservationStabilityGate.Result.WAIT,"legacy whole-key comparison not widened");
            check(g.sample(1400,b,true)==ObservationStabilityGate.Result.READY,"legacy stable whole key remains valid");
        });
        one("classified_gate_missing_previous_does_not_install_current_key",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");
            check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.WAIT,"no previously accepted Gate sample");
            check(g.sample(1200,b,true)==ObservationStabilityGate.Result.WAIT,"unsuccessful classified API did not install a key");
            check(g.sample(1400,b,true)==ObservationStabilityGate.Result.READY,"ordinary actual fallback starts at its own timestamp");
        });
        one("classified_gate_expected_time_mismatch_preserves_prior_evidence",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(g.sampleClassifiedPair(1200,a,999,b,true)==ObservationStabilityGate.Result.WAIT,"caller cannot substitute an earlier accepted timestamp");
            check(g.sample(1200,a,true)==ObservationStabilityGate.Result.READY,"unmatched classified request did not replace old evidence");
        });
        one("classified_gate_expected_key_mismatch_falls_back_to_actual_key",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(g.sampleClassifiedPair(1200,key("invented-before"),1000,b,true)==ObservationStabilityGate.Result.WAIT,"caller must match exact prior value");
            check(g.sample(1200,b,true)==ObservationStabilityGate.Result.WAIT,"ordinary fallback receives actual second key");
            check(g.sample(1400,b,true)==ObservationStabilityGate.Result.READY,"only a fresh actual fallback interval settles");
        });
        for(String kind:Arrays.asList("package","window","rotation","left","top","right","bottom","prior_truncated","actual_truncated")){
            one("classified_gate_"+kind+"_mismatch_cannot_settle_or_replace_prior",()->{
                ObservationStabilityGate g=gate();
                ObservationStabilityGate.FrameKey a=new ObservationStabilityGate.FrameKey("ctrip.android.view",96,0,0,0,1224,2992,"whole-before","prior_truncated".equals(kind));
                ObservationStabilityGate.FrameKey b=new ObservationStabilityGate.FrameKey("package".equals(kind)?"other.package":"ctrip.android.view",
                        "window".equals(kind)?97:96,"rotation".equals(kind)?1:0,"left".equals(kind)?1:0,
                        "top".equals(kind)?1:0,"right".equals(kind)?1223:1224,"bottom".equals(kind)?2991:2992,
                        "whole-after","actual_truncated".equals(kind));
                initial(g,a);
                check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.WAIT,"foreign identity or truncated graph cannot be a classified complete pair");
                check(g.sample(1200,a,true)==ObservationStabilityGate.Result.READY,"legacy original-key state was not overwritten");
            });
        }
        for(String kind:Arrays.asList("expected","actual")){
            one("classified_gate_null_"+kind+"_cannot_settle",()->{
                ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
                check(g.sampleClassifiedPair(1200,"expected".equals(kind)?null:a,1000,"actual".equals(kind)?null:b,true)
                        ==ObservationStabilityGate.Result.WAIT,"null is never a complete native pair");
                check(g.sample(1200,a,true)==ObservationStabilityGate.Result.READY,"null argument did not replace old key");
            });
        }
        one("classified_gate_original_9999_allowed_10000_settle_deadline_rejected",()->{
            ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");
            ObservationStabilityGate inside=new ObservationStabilityGate(0,12000);
            check(inside.sample(9799,a,true)==ObservationStabilityGate.Result.WAIT,"late but original initial sample");
            check(inside.sampleClassifiedPair(9999,a,9799,b,true)==ObservationStabilityGate.Result.READY,"last millisecond inside original settle limit");
            ObservationStabilityGate boundary=new ObservationStabilityGate(0,12000);
            check(boundary.sample(9800,a,true)==ObservationStabilityGate.Result.WAIT,"first sample still inside original settle limit");
            check(boundary.sampleClassifiedPair(10000,a,9800,b,true)==ObservationStabilityGate.Result.EXPIRED,"capture margin is not a settle extension");
            check(boundary.requestAlive(10000,true),"original separate capture lifetime remains observable without granting settle");
        });
        one("classified_gate_earlier_task_deadline_still_clips_sample_pair",()->{
            ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");
            long deadline=ObservationStabilityGate.requestDeadline(1000,1200);
            check(deadline==1200,"original shorter task budget");
            ObservationStabilityGate g=new ObservationStabilityGate(1000,deadline);initial(g,a);
            check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.EXPIRED,"pair cannot consume time at task deadline");
        });
        one("classified_gate_backward_clock_is_expired_without_key_substitution",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(g.requestAlive(1300,true),"clock already advanced in original owner");
            check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.EXPIRED,"clock reversal refused");
        });
        one("classified_gate_cancellation_and_retirement_remain_hard_refusals",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(g.sampleClassifiedPair(1200,a,1000,b,false)==ObservationStabilityGate.Result.CANCELLED,"current cancellation refuses pair");
            g.retire();
            check(g.sampleClassifiedPair(1400,a,1000,b,true)==ObservationStabilityGate.Result.CANCELLED,"retirement cannot be revived by allowed=true");
        });
        one("classified_gate_boundary_reset_invalidates_old_pair_without_renewing_deadline",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            g.resetEvidence();
            check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.WAIT,"old candidate cannot survive reset");
            check(g.sample(1200,b,true)==ObservationStabilityGate.Result.WAIT,"a new actual first sample is still required");
            check(g.sampleClassifiedPair(11000,b,1200,key("third-whole"),true)==ObservationStabilityGate.Result.EXPIRED,"reset does not renew original ten seconds");
        });
        one("classified_gate_ready_pair_cannot_be_replayed_for_later_capture_or_retry",()->{
            ObservationStabilityGate g=gate();ObservationStabilityGate.FrameKey a=key("whole-before"),b=key("whole-after");initial(g,a);
            check(g.sampleClassifiedPair(1200,a,1000,b,true)==ObservationStabilityGate.Result.READY,"first actual pair");
            check(g.sampleClassifiedPair(1400,a,1000,b,true)==ObservationStabilityGate.Result.WAIT,"old expected key/time no longer owns Gate evidence");
            g.resetEvidence();
            check(g.sampleClassifiedPair(1600,b,1200,key("whole-third"),true)==ObservationStabilityGate.Result.WAIT,"screenshot retry/reset requires new full samples");
        });
        List<String> names=new ArrayList<String>();boolean all=true;
        for(Map<String,Object> row:results){names.add((String)row.get("name"));all&=Boolean.TRUE.equals(row.get("passed"));}
        check(new HashSet<String>(names).size()==names.size(),"unique concrete Gate cases");
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.ctrip-form-sampling-gate-cases.v1");
        report.put("cases",results.size());report.put("assertions",assertions);report.put("case_names",names);report.put("results",results);
        report.put("all_pass",all);report.put("complete_form_classification_proved_by_this_class",false);report.put("phone_operations",0);
        Files.write(Paths.get(args[0]),(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        if(!all)throw new AssertionError("actual Gate failure; original report retained");
    }
}
