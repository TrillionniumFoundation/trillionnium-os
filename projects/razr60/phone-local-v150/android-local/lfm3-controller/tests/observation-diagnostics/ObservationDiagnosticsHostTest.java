package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

final class ObservationDiagnosticsHostTest {
    static ObservationDiagnostics fresh(){return new ObservationDiagnostics(DiagnosticChecks.TASK,DiagnosticChecks.REQUEST,
            DiagnosticChecks.OWNER,DiagnosticChecks.APP,DiagnosticChecks.GENERATION,9,1,1000,11000);}
    static JSONObject json(ObservationDiagnostics d,long now){return new JSONObject(d.snapshot(now));}
    static void pure()throws Exception{
        DiagnosticChecks.run("phase_roundtrip_preserves_cumulative_time_and_max",()->{
            ObservationDiagnostics d=fresh();d.phase("sample_graph",1010);d.phase("sample_gap",1040);d.phase("sample_graph",1080);d.finish("failed",1100);
            JSONObject phases=json(d,9999).getJSONObject("phases"),graph=phases.getJSONObject("sample_graph");
            DiagnosticChecks.check(graph.getLong("count")==2&&graph.getLong("total_ms")==50&&graph.getLong("max_ms")==30,"phase accumulation");
            DiagnosticChecks.check(phases.getJSONObject("queued").getLong("total_ms")==10&&phases.getJSONObject("sample_gap").getLong("total_ms")==40,"all phases conserved");
        });
        DiagnosticChecks.run("phase_counts_measure_elapsed_not_CPU",()->{
            ObservationDiagnostics d=fresh();d.phase("png_encode",1000);d.phase("png_fsync",1007);d.phase("png_hash",1011);d.finish("published",1020);
            JSONObject j=json(d,1020);DiagnosticChecks.check(j.getBoolean("phase_times_are_elapsed_not_cpu"),"CPU attribution forbidden");
            DiagnosticChecks.check(j.getJSONObject("phases").getJSONObject("png_encode").getLong("total_ms")==7,"encode elapsed");
        });
        DiagnosticChecks.run("target_unknown_and_other_event_categories_are_distinct",()->{
            ObservationDiagnostics d=fresh();d.note(ObservationDiagnostics.Event.EVENT_TARGET);d.note(ObservationDiagnostics.Event.EVENT_UNKNOWN);d.note(ObservationDiagnostics.Event.EVENT_UNKNOWN);
            JSONObject e=json(d,1000).getJSONObject("events");DiagnosticChecks.check(e.getInt("EVENT_TARGET")==1&&e.getInt("EVENT_UNKNOWN")==2&&e.length()==2,"event categories");
        });
        DiagnosticChecks.run("sample_key_changes_and_reset_are_distinct",()->{
            ObservationDiagnostics d=fresh();String a=DiagnosticChecks.repeat('a',64),b=DiagnosticChecks.repeat('b',64);
            d.graph("sample_graph",a,a,a,a,false,1000);d.graph("sample_graph",a,a,a,a,false,1001);d.graph("sample_graph",b,b,b,b,false,1002);d.reset();d.graph("sample_graph",a,a,a,a,false,1003);
            DiagnosticChecks.check(json(d,1003).getJSONObject("events").getInt("SAMPLE_KEY_CHANGED")==1,"reset cannot invent change");
            d.missingSample();d.graph("sample_graph",b,b,b,b,false,1004);
            DiagnosticChecks.check(json(d,1004).getJSONObject("events").getInt("SAMPLE_KEY_CHANGED")==1,"null sample resets prior key");
        });
        DiagnosticChecks.run("fixed_history_overflow_drops_diagnostics_only",()->{
            ObservationDiagnostics d=fresh();String a=DiagnosticChecks.OWNER;
            for(int i=0;i<1000;i++){d.phase(i%2==0?"sample_graph":"sample_gap",1000+i);d.graph("sample_graph",a,a,a,a,false,1000+i);}
            JSONObject j=json(d,2000);DiagnosticChecks.check(j.getJSONArray("last_transitions").length()==16&&j.getLong("transition_count")==1000&&j.getBoolean("transitions_truncated"),"transition bound");
            DiagnosticChecks.check(j.getJSONArray("last_graphs").length()==6&&j.getLong("graph_record_count")==1000&&j.getBoolean("graph_records_truncated"),"frame bound");
            DiagnosticChecks.check(d.deadline==11000&&!j.getBoolean("changes_deadline"),"no renewed deadline");
        });
        DiagnosticChecks.run("maximum_pretty_record_fits_fixed_16KiB",()->{
            ObservationDiagnostics d=new ObservationDiagnostics(DiagnosticChecks.TASK,DiagnosticChecks.REQUEST,DiagnosticChecks.OWNER,
                    DiagnosticChecks.repeat('p',128),DiagnosticChecks.GENERATION,2147483647,96,0,Long.MAX_VALUE);
            String[] phases={"queued","sample_graph","sample_gap","screenshot_callback","screenshot_copy","screenshot_graph","png_encode","png_fsync","png_hash","saved_graph","publish","retry_gap"};
            for(int i=0;i<32;i++){d.phase(phases[i%phases.length],Long.MAX_VALUE-100+i);d.graph("sample_graph",DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,true,Long.MAX_VALUE-100+i);}
            for(ObservationDiagnostics.Event e:ObservationDiagnostics.Event.values())d.note(e);
            d.finish("failed",Long.MAX_VALUE);int length=json(d,Long.MAX_VALUE).toString(2).getBytes(StandardCharsets.UTF_8).length;
            DiagnosticChecks.check(length<=ObservationDiagnostics.MAX_JSON_BYTES,"real JSON pretty byte cap "+length);
        });
        DiagnosticChecks.run("terminal_snapshot_does_not_claim_worker_drain",()->{
            ObservationDiagnostics d=fresh();d.worker(true);d.finish("failed",1100);String first=json(d,1100).toString();
            d.worker(false);d.note(ObservationDiagnostics.Event.PUBLISHED);d.phase("publish",1200);
            JSONObject j=json(d,9999);DiagnosticChecks.check(first.equals(j.toString()),"terminal values frozen");
            DiagnosticChecks.check(j.getBoolean("worker_active_at_last_diagnostic_update")&&!j.getBoolean("worker_drained_proved_by_this_record"),"retirement is not drain");
        });
        DiagnosticChecks.run("snapshot_mutation_cannot_mutate_tracker",()->{
            ObservationDiagnostics d=fresh();d.phase("sample_gap",1010);Map<String,Object> view=d.snapshot(1010);view.clear();
            DiagnosticChecks.check("sample_gap".equals(json(d,1010).getString("phase")),"independent snapshot");
        });
        DiagnosticChecks.run("different_requests_do_not_share_counter_state",()->{
            ObservationDiagnostics a=fresh(),b=fresh();a.note(ObservationDiagnostics.Event.SAMPLE_START);a.finish("failed",1100);
            DiagnosticChecks.check(json(b,1100).getJSONObject("events").length()==0&&!json(b,1100).getBoolean("request_terminal_observed"),"cross request state");
        });
        DiagnosticChecks.run("clock_regression_is_explicit_without_gate_changes",()->{
            ObservationDiagnostics d=fresh();d.phase("sample_graph",1100);d.phase("sample_gap",1050);
            DiagnosticChecks.check(json(d,1100).getBoolean("clock_regressed")&&d.deadline==11000,"diagnostic clamp only");
        });
        DiagnosticChecks.run("fixed_vocabulary_rejects_arbitrary_phase_or_hash_text",()->{
            ObservationDiagnostics d=fresh();d.phase("private screen text",1001);d.graph("sample_graph","private",DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,false,1002);
            String raw=json(d,1002).toString();DiagnosticChecks.check(!raw.contains("private")&&json(d,1002).getInt("graph_record_count")==0,"content rejected");
        });
        DiagnosticChecks.run("pure_constructor_rejects_unbounded_identity_and_sequence",()->{
            int failures=0;for(int sequence:new int[]{0,97})try{new ObservationDiagnostics(DiagnosticChecks.TASK,DiagnosticChecks.REQUEST,DiagnosticChecks.OWNER,DiagnosticChecks.APP,DiagnosticChecks.GENERATION,9,sequence,1000,11000);}catch(IllegalArgumentException expected){failures++;}
            DiagnosticChecks.check(failures==2,"sequence bound");
            try{new ObservationDiagnostics("not-task",DiagnosticChecks.REQUEST,DiagnosticChecks.OWNER,DiagnosticChecks.APP,DiagnosticChecks.GENERATION,9,1,1000,11000);throw new AssertionError("bad task accepted");}catch(IllegalArgumentException expected){DiagnosticChecks.check(true,"invalid task refused");}
        });
        DiagnosticChecks.run("actual_stability_gate_timeline_identical_with_diagnostics",()->{
            ObservationStabilityGate plain=new ObservationStabilityGate(1000,11000),traced=new ObservationStabilityGate(1000,11000);ObservationDiagnostics d=fresh();
            ObservationStabilityGate.FrameKey a=new ObservationStabilityGate.FrameKey(DiagnosticChecks.APP,71,0,0,0,1224,2992,"a",false),b=new ObservationStabilityGate.FrameKey(DiagnosticChecks.APP,71,0,0,0,1224,2992,"b",false);
            long[] times={1000,1100,1200,1300,1500,1700,1800,2000,10999,11000};
            ObservationStabilityGate.FrameKey[] keys={a,a,a,b,null,b,b,b,b,b};
            for(int i=0;i<times.length;i++){if(i==6){plain.resetEvidence();traced.resetEvidence();d.reset();}
                ObservationStabilityGate.Result p=plain.sample(times[i],keys[i],true),t=traced.sample(times[i],keys[i],true);d.note(ObservationDiagnostics.Event.valueOf("SAMPLE_"+t.name()));
                DiagnosticChecks.check(p==t&&plain.nextSampleDelay(times[i])==traced.nextSampleDelay(times[i]),"changed gate at "+i);}
            plain.retire();traced.retire();DiagnosticChecks.check(plain.sample(11001,a,true)==traced.sample(11001,a,true),"retirement changed");
        });
    }
    public static void main(String[] args)throws Exception{
        pure();ObserverPipelineHost.diagnosticTests();DiagnosticGraphHost.runTests();DiagnosticControllerHost.runTests();DiagnosticChecks.finish(args[0]);
    }
}
