package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual immutable census adapter, tracker and Service private serializer.
 * Android frames/windows/clock are explicit copied host values, never device evidence. */
final class PrivateCensusDiagnosticsHostTest {
    private static void check(boolean value,String why){DiagnosticChecks.check(value,why);}
    private static ObservationDiagnostics.CensusStamp stamp(DiagnosticGraphHost.Graph graph){
        ObservationDiagnostics.CensusStamp value=DiagnosticGraphHost.fullStamp(graph);check(value!=null,"actual complete-census adapter");return value;
    }
    private static ObservationDiagnostics failure(DiagnosticGraphHost.Graph before,DiagnosticGraphHost.Graph after){
        ObservationDiagnostics values=DiagnosticGraphHost.tracker();
        values.fullGraphChange("saved_graph",stamp(before),stamp(after),1500);values.finish("failed",1800);return values;
    }
    private static JSONObject wire(ObservationDiagnostics values)throws Exception{
        String text=ObserverPipelineHost.actualPrivateSnapshot(values).call();JSONObject raw=new JSONObject(text);
        check(text.getBytes(StandardCharsets.UTF_8).length<=2097152&&raw.toString(2).getBytes(StandardCharsets.UTF_8).length<=2097152,"real UTF8 compact and pretty private bound");
        check(raw.getInt("additional_node_samples")==0&&raw.getInt("additional_screenshots")==0&&!raw.getBoolean("changes_deadline"),"no new observation work or time");
        check(!raw.getBoolean("grants_action_authority")&&!raw.getBoolean("grants_publication")&&!raw.getBoolean("business_verified")&&!raw.getBoolean("sent_to_model"),"no authority or model channel");
        return raw;
    }
    private static JSONObject byPath(JSONArray rows,String path){
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);
        throw new AssertionError("path missing "+path);
    }
    private static void noRaw(JSONObject value,String expected){
        check(!value.getBoolean("complete_pair_recorded")&&!value.getBoolean("node_text_recorded")&&value.getInt("raw_pair_count")==0,"no false full pair");
        check(!value.has("before")&&!value.has("after")&&expected.equals(value.getString("status")),"explicit refusal without partial raw values");
    }
    private static ObservationDiagnostics ctripTracker(){
        return new ObservationDiagnostics(DiagnosticChecks.TASK,DiagnosticChecks.REQUEST,DiagnosticChecks.OWNER,
                "ctrip.android.view",DiagnosticChecks.GENERATION,9,2,1000,13000);
    }
    private static DiagnosticGraphHost.Graph ctripGraph(int count,long begin,long end,String text){
        DiagnosticGraphHost.Graph g=DiagnosticGraphHost.fullGraph(count);g.packageName="ctrip.android.view";
        for(int i=0;i<count;i++)DiagnosticGraphHost.change(g,i,"package",g.packageName);
        g.readStartedElapsedMs=begin;g.readCompletedElapsedMs=end;
        g.profileWindow=new DiagnosticGraphHost.ProfileIdentity(DiagnosticGraphHost.profile(401,"11111111-2222-3333-4444-555555555555"));
        if(text!=null)DiagnosticGraphHost.change(g,count-1,"text",text);return g;
    }
    private static Map<String,Object> mark(long events,long content,long boundary){
        Map<String,Object> m=new LinkedHashMap<String,Object>();m.put("events",events);m.put("unknown",0L);
        m.put("content",content);m.put("boundary",boundary);return m;
    }
    private static void sampled(ObservationDiagnostics d,DiagnosticGraphHost.Graph graph,Map<String,Object> start,Map<String,Object> end,long at){
        d.note(ObservationDiagnostics.Event.SAMPLE_START);
        d.sampleCensus(DiagnosticGraphHost.fullStamp(graph),start,end,at,at);
    }
    private static void completeSampleCases()throws Exception{
        DiagnosticChecks.run("ctrip_failed_seal_keeps_last_two_actual_complete_samples_only",()->{
            ObservationDiagnostics d=ctripTracker();
            DiagnosticGraphHost.Graph a=ctripGraph(3,1010,1100,"FIRST_SAMPLE"),b=ctripGraph(3,1200,1300,"SECOND_SAMPLE"),
                    c=ctripGraph(3,1500,1600,"LAST_COMPLETE_SAMPLE");
            sampled(d,a,mark(0,0,0),mark(3,1,2),1100);sampled(d,b,mark(3,1,2),mark(6,2,4),1300);
            d.graphStale("ax_seal_graph","stale:后台子节点已不可用，需重新观察",true,"0/1",mark(6,2,4),mark(8,4,4),1350);
            d.note(ObservationDiagnostics.Event.SAMPLE_START);d.sampleCensus(null,mark(8,4,4),mark(8,4,4),1400,1400);
            sampled(d,c,mark(8,4,4),mark(10,5,5),1600);
            noRaw(wire(d),"request_not_terminal");d.finish("failed",1700);JSONObject raw=wire(d);
            check(raw.getBoolean("complete_pair_recorded")&&raw.getString("status").equals("complete_sample_pair_unpublished"),"failed sample fallback is explicit and complete");
            check(!raw.toString().contains("FIRST_SAMPLE")&&raw.toString().contains("SECOND_SAMPLE")&&raw.toString().contains("LAST_COMPLETE_SAMPLE"),"exactly the last two complete samples; no failed half-graph");
            JSONObject facts=raw.getJSONObject("selected_pair_sampling");
            check(facts.getLong("complete_sample_count")==3&&!facts.getBoolean("samples_consecutive")
                    &&facts.getJSONObject("before").getLong("sample_ordinal")==2&&facts.getJSONObject("after").getLong("sample_ordinal")==4,"partial read gap remains visible");
            check(!facts.getBoolean("published_pair")&&!facts.getBoolean("stability_proved")&&!facts.getBoolean("events_admitted_for_publication"),"samples never become a sealed or stable pair");
            check(raw.getJSONObject("after").getJSONObject("identity").getInt("profile_full_uid")==1010485
                    &&raw.getJSONObject("after").getJSONObject("read").getLong("read_completed_elapsed_ms")==1600,"actual UID and original read clock preserved");
            String frozen=raw.toString();a.nativeActionNodes.clear();b.nativeActionNodes.clear();c.nativeActionNodes.clear();
            check(frozen.equals(wire(d).toString()),"Graph release does not mutate retained immutable values");
            check(!new JSONObject(ObserverPipelineHost.actualSnapshot(d).call()).toString().contains("LAST_COMPLETE_SAMPLE"),"raw values stay out of summary/model channel");
        });
        for(final String changed:Arrays.asList("task","owner","uid","token","window","selection","clock","deadline","profile","incomplete")){
            DiagnosticChecks.run("ctrip_sample_fallback_refuses_"+changed,()->{
                ObservationDiagnostics d=ctripTracker();DiagnosticGraphHost.Graph a=ctripGraph(3,1010,1100,"BOUND_A"),b=ctripGraph(3,1200,1300,"REFUSED_B");
                if("task".equals(changed))b.nativeActionTaskId=DiagnosticChecks.repeat('9',32);
                if("owner".equals(changed))b.backgroundOwnerSha=DiagnosticChecks.repeat('9',64);
                if("uid".equals(changed))b.profileWindow.fields.put("profile_full_uid",1010486);
                if("token".equals(changed))b.profileWindow.fields.put("profile_task_token_id","99999999-2222-3333-4444-555555555555");
                if("window".equals(changed)){b.windowId=72;for(int i=0;i<3;i++)DiagnosticGraphHost.change(b,i,"window_id",72);}
                if("selection".equals(changed))b.nativeActionSelectionSha=DiagnosticChecks.repeat('9',64);
                if("clock".equals(changed))b.readStartedElapsedMs=1099;
                if("deadline".equals(changed))b.readCompletedElapsedMs=13000;
                if("profile".equals(changed))b.profileWindow=null;
                if("incomplete".equals(changed))b.nativeObservationComplete=false;
                sampled(d,a,mark(0,0,0),mark(1,0,1),1100);
                sampled(d,b,mark(1,0,1),mark(2,1,1),"deadline".equals(changed)?13000:1300);
                d.finish("failed",13100);JSONObject raw=wire(d);noRaw(raw,"no_same_identity_complete_sample_pair");
                check(!raw.toString().contains("BOUND_A")&&!raw.toString().contains("REFUSED_B"),"no foreign or partial raw pair");
            });
        }
        DiagnosticChecks.run("ctrip_sample_pair_budget_refuses_whole_raw_pair_without_truncation",()->{
            ObservationDiagnostics d=ctripTracker();DiagnosticGraphHost.Graph a=ctripGraph(120,1010,1100,null),b=ctripGraph(120,1200,1300,null);
            for(int i=0;i<120;i++){DiagnosticGraphHost.change(a,i,"label",DiagnosticChecks.repeat('A',1900));DiagnosticGraphHost.change(b,i,"label",DiagnosticChecks.repeat('B',1900));}
            sampled(d,a,mark(0,0,0),mark(0,0,0),1100);sampled(d,b,mark(0,0,0),mark(0,0,0),1300);d.finish("failed",1400);
            JSONObject raw=wire(d);noRaw(raw,"complete_pair_value_budget_exceeded");check(raw.getBoolean("raw_pair_omitted_for_budget"),"explicit existing 2 MiB refusal");
        });
        DiagnosticChecks.run("ctrip_sample_fallback_does_not_replace_original_full_seal_pair",()->{
            ObservationDiagnostics d=ctripTracker();DiagnosticGraphHost.Graph a=ctripGraph(3,1010,1100,"SEALED_A"),b=ctripGraph(3,1200,1300,"SEALED_B"),c=ctripGraph(3,1500,1600,"LATER_SAMPLE");
            sampled(d,a,mark(0,0,0),mark(0,0,0),1100);sampled(d,b,mark(0,0,0),mark(0,0,0),1300);
            d.fullGraphChange("ax_seal_graph",stamp(a),stamp(b),1400);sampled(d,c,mark(0,0,0),mark(0,0,0),1600);d.finish("failed",1700);
            JSONObject raw=wire(d);check(raw.getString("selected_pair_stage").equals("ax_seal_graph")&&!raw.has("selected_pair_sampling")
                    &&raw.toString().contains("SEALED_A")&&!raw.toString().contains("LATER_SAMPLE"),"existing complete refusal pair has priority");
        });
        DiagnosticChecks.run("ctrip_published_request_never_exports_complete_sample_values",()->{
            ObservationDiagnostics d=ctripTracker();sampled(d,ctripGraph(3,1010,1100,"PUBLISHED_PRIVATE_A"),mark(0,0,0),mark(0,0,0),1100);
            sampled(d,ctripGraph(3,1200,1300,"PUBLISHED_PRIVATE_B"),mark(0,0,0),mark(0,0,0),1300);d.finish("published",1400);
            JSONObject raw=wire(d);noRaw(raw,"request_published");check(!raw.has("selected_pair_sampling")&&!raw.toString().contains("PUBLISHED_PRIVATE"),"successful publication clears fallback values");
        });
        DiagnosticChecks.run("ctrip_stale_cause_and_event_watermarks_are_actual_bounded_frozen_values",()->{
            ObservationDiagnostics d=ctripTracker();Map<String,Object> begin=mark(49,0,49),end=mark(54,5,49);
            d.graphStale("ax_seal_graph","stale:后台子节点已不可用，需重新观察",true,"0/1/2",begin,end,1200);
            begin.put("events",999L);end.put("content",999L);d.finish("failed",1300);JSONObject raw=wire(d);
            JSONObject row=raw.getJSONArray("native_graph_stale_reads").getJSONObject(0);
            check(row.getString("phase").equals("ax_seal_graph")&&row.getString("cause").equals("child_refresh_unavailable")
                    &&row.getString("node_path").equals("0/1/2")&&row.getBoolean("typed_child_unavailable"),"actual typed exception, phase and path");
            check(row.getJSONObject("read_start_watermark").getLong("events")==49&&row.getJSONObject("failure_watermark").getLong("content")==5
                    &&!row.getBoolean("complete_graph_returned"),"exact pre-failure watermarks, never a complete graph");
            String frozen=raw.toString();d.graphStale("sample_graph","stale:后台根节点已不可用，需重新观察",false,null,mark(0,0,0),mark(0,0,0),1400);
            check(frozen.equals(wire(d).toString()),"terminal diagnostics cannot change");
        });
        DiagnosticChecks.run("ctrip_stale_diagnostic_limits_and_unknown_causes_do_not_invent_paths",()->{
            ObservationDiagnostics d=ctripTracker();
            for(int i=0;i<7;i++)d.graphStale("sample_graph","stale:UNRECOGNIZED_PRIVATE_TEXT",false,i==6?DiagnosticChecks.repeat('9',241):null,mark(i,0,i),mark(i+1,0,i+1),1100+i);
            d.finish("failed",1200);JSONObject raw=wire(d);JSONArray rows=raw.getJSONArray("native_graph_stale_reads");
            check(rows.length()==4&&raw.getLong("native_graph_stale_read_count")==7,"last four fixed-size actual failures");
            JSONObject last=rows.getJSONObject(3);check(last.getString("cause").equals("unclassified_stale")&&last.isNull("node_path")&&!last.getBoolean("node_path_recorded"),"unknown cause/path stays unknown");
            check(!raw.toString().contains("UNRECOGNIZED_PRIVATE_TEXT"),"exception free text is not retained");
        });
    }
    static void run()throws Exception{
        PrivateCensusFileHost.run();
        completeSampleCases();
        DiagnosticChecks.run("private_full_280_node_pair_survives_summary_detail_budget",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(280),b=DiagnosticGraphHost.fullGraph(280);
            a.readStartedElapsedMs=1010;a.readCompletedElapsedMs=1100;b.readStartedElapsedMs=1300;b.readCompletedElapsedMs=1450;
            for(int i=1;i<=20;i++)DiagnosticGraphHost.change(b,i,"text","RAW_NATIVE_TEXT_"+i);
            DiagnosticGraphHost.change(b,279,"text","LAST_NATIVE_NODE_MUST_SURVIVE");
            ObservationDiagnostics values=failure(a,b);JSONObject raw=wire(values);
            check(raw.getBoolean("complete_pair_recorded")&&raw.getInt("raw_pair_count")==1,"complete last pair retained");
            JSONObject before=raw.getJSONObject("before"),after=raw.getJSONObject("after");
            check(before.getJSONArray("native_nodes").length()==280&&after.getJSONArray("native_nodes").length()==280,"all nodes, including unretained UI rows");
            check(byPath(after.getJSONArray("native_nodes"),"0/278").getString("text").equals("LAST_NATIVE_NODE_MUST_SURVIVE"),"final full-tree leaf preserved");
            check(before.getJSONObject("read").getLong("read_started_elapsed_ms")==1010&&after.getJSONObject("read").getLong("read_completed_elapsed_ms")==1450,"actual completed read intervals");
            check(raw.getString("selected_pair_stage").equals("saved_graph")&&raw.getLong("selected_pair_compared_elapsed_ms")==1500,"comparison phase and time bound");
            String summary=ObserverPipelineHost.actualSnapshot(values).call();
            check(!summary.contains("LAST_NATIVE_NODE_MUST_SURVIVE")&&!summary.contains("RAW_NATIVE_TEXT_"),"original summary contains hashes only");
            check(new JSONObject(summary).toString(2).getBytes(StandardCharsets.UTF_8).length<=16384,"original summary cap preserved");
        });
        DiagnosticChecks.run("private_snapshot_is_deeply_immutable_after_graph_reuse",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);
            List<Integer> nestedBounds=new ArrayList<Integer>(Arrays.asList(0,0,1080,2400));
            Map<String,Object> window=new LinkedHashMap<String,Object>();window.put("bounds",nestedBounds);
            List<Map<String,Object>> windows=new ArrayList<Map<String,Object>>();windows.add(window);
            Map<String,Object> observed=new LinkedHashMap<String,Object>();observed.put("windows",windows);
            a.nativeActionWindows=observed;b.nativeActionWindows=observed;
            DiagnosticGraphHost.change(b,2,"text","FROZEN_PRIVATE_BODY");ObservationDiagnostics values=failure(a,b);
            String original=wire(values).toString();a.nativeActionNodes.clear();b.nativeActionNodes.clear();
            nestedBounds.set(0,999);window.put("bounds","mutated");windows.clear();observed.clear();
            check(original.equals(wire(values).toString()),"graph/window alias cannot mutate copied values");
            JSONObject returned=wire(values);returned.getJSONObject("after").getJSONArray("native_nodes").getJSONObject(0).put("text","mutated");
            check(original.equals(wire(values).toString()),"returned JSON does not mutate immutable pair");
        });
        DiagnosticChecks.run("private_latest_complete_pair_replaces_previous_pair_once",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3),c=DiagnosticGraphHost.fullGraph(3);
            DiagnosticGraphHost.change(b,1,"text","OLDER_PAIR");DiagnosticGraphHost.change(c,2,"text","LATEST_PAIR");
            ObservationDiagnostics values=DiagnosticGraphHost.tracker();values.fullGraphChange("screenshot_graph",stamp(a),stamp(b),1200);
            values.fullGraphChange("saved_graph",stamp(a),stamp(c),1400);values.finish("failed",1500);
            JSONObject raw=wire(values);check(raw.getInt("raw_pair_count")==1&&raw.getLong("selected_pair_ordinal")==2&&raw.getLong("full_graph_change_count")==2,"last complete pair and count");
            check(!raw.toString().contains("OLDER_PAIR")&&raw.toString().contains("LATEST_PAIR"),"old pair released");
        });
        DiagnosticChecks.run("private_foreign_identity_cannot_replace_valid_pair",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3),foreign=DiagnosticGraphHost.fullGraph(3);
            DiagnosticGraphHost.change(b,1,"text","BOUND_PAIR");foreign.nativeActionTaskId="99999999999999999999999999999999";
            DiagnosticGraphHost.change(foreign,2,"text","FOREIGN_PAIR");
            ObservationDiagnostics values=DiagnosticGraphHost.tracker();values.fullGraphChange("saved_graph",stamp(a),stamp(b),1200);
            values.fullGraphChange("saved_graph",stamp(a),stamp(foreign),1400);values.finish("failed",1500);
            JSONObject raw=wire(values);check(raw.getLong("selected_pair_ordinal")==1&&raw.getLong("full_graph_change_count")==2,"last eligible pair explicitly older than latest refused comparison");
            check(raw.toString().contains("BOUND_PAIR")&&!raw.toString().contains("FOREIGN_PAIR"),"foreign raw values never retained");
        });
        DiagnosticChecks.run("private_unfinished_trace_returns_only_metadata",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);DiagnosticGraphHost.change(b,1,"text","PENDING_BODY");
            ObservationDiagnostics values=DiagnosticGraphHost.tracker();values.fullGraphChange("saved_graph",stamp(a),stamp(b),1200);
            noRaw(wire(values),"request_not_terminal");check(!wire(values).getBoolean("request_terminal_observed"),"no synthetic terminal");
        });
        DiagnosticChecks.run("private_published_request_releases_and_never_exports_pair",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);DiagnosticGraphHost.change(b,1,"text","PUBLISHED_BODY");
            ObservationDiagnostics values=DiagnosticGraphHost.tracker();values.fullGraphChange("saved_graph",stamp(a),stamp(b),1200);
            values.published("44444444444444444444444444444444",1300);noRaw(wire(values),"request_published");
        });
        DiagnosticChecks.run("private_late_worker_update_cannot_change_terminal_pair",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3),late=DiagnosticGraphHost.fullGraph(3);
            DiagnosticGraphHost.change(b,1,"text","TERMINAL_BODY");DiagnosticGraphHost.change(late,2,"text","LATE_WORKER_BODY");
            ObservationDiagnostics values=failure(a,b);String original=wire(values).toString();
            values.fullGraphChange("saved_graph",stamp(a),stamp(late),9000);values.worker(true);values.phase("saved_graph",9001);
            check(original.equals(wire(values).toString()),"late worker changes ignored after trace terminal");
        });
        DiagnosticChecks.run("private_missing_census_remains_explicitly_unavailable",()->{
            ObservationDiagnostics values=DiagnosticGraphHost.tracker();values.fullGraphChange("saved_graph",null,null,1200);values.finish("failed",1300);
            noRaw(wire(values),"no_complete_difference_pair");
        });
        DiagnosticChecks.run("private_read_context_must_be_within_request_and_completed",()->{
            for(int mode=0;mode<3;mode++){
                DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);
                DiagnosticGraphHost.change(b,1,"text","NOT_PROVED_COMPLETE");
                if(mode==0)b.readStartedElapsedMs=999;else if(mode==1)b.readCompletedElapsedMs=1600;else b.readCompletedElapsedMs=900;
                noRaw(wire(failure(a,b)),"complete_pair_context_unavailable");
            }
        });
        DiagnosticChecks.run("private_raw_budget_refusal_never_truncates_and_calls_pair_complete",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(300),b=DiagnosticGraphHost.fullGraph(300);
            for(int i=0;i<300;i++){DiagnosticGraphHost.change(a,i,"label",DiagnosticChecks.repeat('x',4096));DiagnosticGraphHost.change(b,i,"label",DiagnosticChecks.repeat('y',4096));}
            ObservationDiagnostics values=failure(a,b);JSONObject raw=wire(values);
            noRaw(raw,"complete_pair_value_budget_exceeded");check(raw.getBoolean("raw_pair_omitted_for_budget"),"explicit capacity refusal");
            check(raw.getJSONObject("before_summary").getInt("full_native_nodes")==300&&raw.getJSONObject("after_summary").getInt("full_native_nodes")==300,"full compared counts preserved");
            check(!raw.toString().contains(DiagnosticChecks.repeat('x',100))&&raw.toString(2).getBytes(StandardCharsets.UTF_8).length<8192,"no arbitrary truncated prefix stored");
        });
        DiagnosticChecks.run("private_profile_identity_and_reported_window_values_are_preserved",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);
            Map<String,Object> profile=DiagnosticGraphHost.profile(501,"22222222-2222-2222-2222-222222222222");
            a.profileWindow=new DiagnosticGraphHost.ProfileIdentity(profile);b.profileWindow=new DiagnosticGraphHost.ProfileIdentity(profile);
            DiagnosticGraphHost.change(b,1,"text","PROFILE_BODY");JSONObject raw=wire(failure(a,b));
            JSONObject identity=raw.getJSONObject("after").getJSONObject("identity");
            check(identity.getInt("profile_user_id")==10&&identity.getInt("profile_full_uid")==1010485&&identity.getInt("profile_task_id")==501,"exact profile identity retained");
            JSONObject read=raw.getJSONObject("after").getJSONObject("read");
            check(read.getBoolean("reported_windows_complete")&&read.has("reported_windows")&&read.getInt("pending_nodes_at_stop")==0,"already read window and completeness values retained");
            check(!raw.getBoolean("worker_drained_proved_by_this_record"),"diagnostic must not invent cleanup evidence");
        });
    }
}
