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
    static void run()throws Exception{
        PrivateCensusFileHost.run();
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
