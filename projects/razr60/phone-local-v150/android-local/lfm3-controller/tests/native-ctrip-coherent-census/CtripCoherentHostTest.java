package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

/** Counterfactual host qualification over complete archived node values.
 * Android getters, identity, clocks and event arrivals are explicit fixtures.
 * No archived failure is reclassified as a successful device read or task. */
public final class CtripCoherentHostTest {
    private static int assertions;
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static final Map<Boolean,List<Map<String,Object>>> originals=new HashMap<Boolean,List<Map<String,Object>>>();
    private static final Map<Boolean,Map<String,Object>> derived=new HashMap<Boolean,Map<String,Object>>();
    interface Body { Map<String,Object> run() throws Exception; }
    static synchronized void require(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void yes(Map<String,Object> m,String key){require(Boolean.TRUE.equals(m.get(key)),key+": "+m);}
    static void no(Map<String,Object> m,String key){require(Boolean.FALSE.equals(m.get(key)),key+": "+m);}
    static long number(Map<String,Object> m,String key){Object n=m.get(key);require(n instanceof Number,key+" numeric");return ((Number)n).longValue();}
    private static void run(String name,Body body){
        Map<String,Object> record=new LinkedHashMap<String,Object>();record.put("name",name);
        try{record.put("evidence",body.run());record.put("pass",true);}
        catch(Throwable failed){record.put("pass",false);record.put("error_class",failed.getClass().getName());record.put("error",failed.getMessage());}
        results.add(record);System.out.println((Boolean.TRUE.equals(record.get("pass"))?"PASS ":"FAIL ")+name);
    }
    @SuppressWarnings("unchecked")
    static List<Map<String,Object>> original(boolean after)throws Exception{
        if(!originals.containsKey(after)){
            JSONObject archive=new JSONObject(new String(Files.readAllBytes(Paths.get(System.getProperty("hepta.ctrip.coherent.actual"))),StandardCharsets.UTF_8));
            require(archive.getBoolean("complete_pair_recorded")&&!archive.getBoolean("raw_pair_omitted_for_budget")
                    &&archive.getInt("raw_pair_count")==1&&"saved_graph".equals(archive.getString("selected_pair_stage")),"one complete saved-graph original pair");
            JSONObject side=archive.getJSONObject(after?"after":"before"),read=side.getJSONObject("read");
            JSONArray raw=side.getJSONArray("native_nodes");
            require(side.getBoolean("native_nodes_complete")&&read.getBoolean("native_observation_complete")
                    &&read.getBoolean("reported_windows_complete")&&!read.getBoolean("truncated"),"full archived node/window census");
            require(raw.length()==(after?281:283)&&side.getInt("raw_node_count")==raw.length(),"entire original 283/281 membership");
            List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();Set<String> paths=new HashSet<String>();
            for(int i=0;i<raw.length();i++){
                Map<String,Object> n=raw.getJSONObject(i).toMap();
                require(paths.add((String)n.get("path")),"unique original path");rows.add(Collections.unmodifiableMap(new TreeMap<String,Object>(n)));
            }
            originals.put(after,Collections.unmodifiableList(rows));
        }
        return originals.get(after);
    }
    static Map<String,Object> derived(boolean after)throws Exception{
        if(!derived.containsKey(after))derived.put(after,CapturedCtripLabelHost.derive(original(after),null));
        return derived.get(after);
    }
    @SuppressWarnings("unchecked")
    static NativeActionSnapshotCheckHostTest.Fixture fixture(boolean after,boolean coherent)throws Exception{
        NativeActionSnapshotCheckHostTest.Fixture f=FormPairHostTest.managedForm();f.nodes.clear();
        List<Map<String,Object>> rows=coherent?(List<Map<String,Object>>)derived(after).get("nodes"):original(after);
        for(Map<String,Object> row:rows)f.nodes.put((String)row.get("path"),new TreeMap<String,Object>(row));
        f.env.put("window_id",rows.get(0).get("window_id"));f.env.put("root_bounds",rows.get(0).get("bounds"));
        f.env.put("captured_elapsed_ms",after?1100L:1000L);f.env.put("visited",f.nodes.size());
        // These envelope values are deliberately synthetic. Missing original
        // captured clock/event watermarks are never filled into the archive.
        return f;
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> pair(boolean coherent)throws Exception{
        NativeActionSnapshotCheckHostTest.Fixture a=fixture(false,coherent),b=fixture(true,coherent);
        Map<String,Object> proof=NativeCtripFormObservation.compare(a.snapshot(),b.snapshot());
        no(proof,"grants_action_authority");no(proof,"query_history_proved");no(proof,"business_completion_verified");
        yes(proof,"full_census_compared");yes(proof,"fresh_action_validation_required");no(proof,"changed_paths_truncated");
        require(((List<String>)proof.get("protected_subtrees")).equals(Collections.singletonList("0/0/2")),"whole actual form remains protected");
        int protectedCount=0;
        for(String path:a.nodes.keySet())if(path.equals("0/0/2")||path.startsWith("0/0/2/")){
            require(a.nodes.get(path).equals(b.nodes.get(path)),"every protected form value equal");protectedCount++;
        }
        require(protectedCount==28,"entire archived 28-node form");
        Set<String> expected=new TreeSet<String>();Set<String> union=new TreeSet<String>(a.nodes.keySet());union.addAll(b.nodes.keySet());
        for(String p:union)if(!Objects.equals(a.nodes.get(p),b.nodes.get(p)))expected.add(p);
        require(new TreeSet<String>((List<String>)proof.get("changed_paths")).equals(expected),"full difference inventory, not retained summaries");
        for(String p:expected)require(p.equals("0/0/7")||p.startsWith("0/0/7/")||p.equals("0/0/9")||p.startsWith("0/0/9/"),"each actual difference inside original accepted structural branches");
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("proof",proof);result.put("protected_nodes",protectedCount);
        result.put("before_nodes",a.nodes.size());result.put("after_nodes",b.nodes.size());result.put("changed_paths",expected.size());
        result.put("clock_identity_event_context_synthetic",true);result.put("actual_failure_predicate_reconstructed",false);
        return result;
    }
    private static Map<String,Object> refusePair(String kind)throws Exception{
        NativeActionSnapshotCheckHostTest.Fixture a=fixture(false,true),b=fixture(true,true);
        if(kind.equals("protected_date"))NativeActionSnapshotCheckHostTest.changedText(b,"0/0/2/5","11月27日明天");
        else if(kind.equals("query_capability"))b.nodes.get("0/0/2/13").put("enabled",false);
        else if(kind.equals("missing_child"))b.nodes.remove("0/0/7/0");
        else if(kind.equals("interactive_recommendation"))b.nodes.get("0/0/7/0").put("editable",true);
        else if(kind.equals("overlap_form"))b.nodes.get("0/0/7").put("bounds",Arrays.asList(39,500,762,1200));
        else if(kind.equals("window_changed"))b.env.put("window_id",2815);
        else throw new AssertionError("unknown test mutation");
        boolean refused=false;String reason=null;
        try{NativeCtripFormObservation.compare(a.snapshot(),b.snapshot());}
        catch(IllegalArgumentException expected){refused=true;reason=expected.getMessage();}
        require(refused&&reason!=null&&!reason.isEmpty(),"complete original classifier refuses "+kind);
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("mutation",kind);out.put("refused",refused);out.put("reason",reason);return out;
    }
    static void commonPipeline(Map<String,Object> m){
        for(String key:Arrays.asList("deadline_unchanged","no_action_or_business_completion","all_graphs_closed",
                "all_bitmaps_recycled","all_buffers_closed","workers_drained"))yes(m,key);
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> pipeline(String scenario)throws Exception{
        Map<String,Object> m=ObserverPipelineHost.exerciseCoherentPipeline(scenario);commonPipeline(m);
        boolean legacy="untyped_during_encoding".equals(scenario);
        boolean accepted="ordinary_complete_pair".equals(scenario)||legacy;
        require(number(m,"publications")== (accepted?1:0),"same original pipeline publication decision: "+m);
        if(legacy){
            require(number(m,"new_png_files")==1&&number(m,"history_artifacts")==0&&number(m,"full_reads")==3,
                    "legacy control remains the original sealed window-only path");
            require(number(m,"events")==1&&number(m,"content_events")==0&&number(m,"unknown_events")==0&&number(m,"boundary_events")==0,
                    "one actual legacy event, not typed-content recovery");
            Map<String,Object> proof=(Map<String,Object>)m.get("capture_evidence");
            require("pre_encoding_paired_history".equals(proof.get("mode")),"legacy control is only historical paired evidence");
            no(proof,"grants_action_authority");no(proof,"business_completion_verified");yes(proof,"fresh_action_validation_required");
        }else if(accepted){
            require(number(m,"new_png_files")==1&&number(m,"history_artifacts")==1,"single actual generated PNG/history");
            Map<String,Object> proof=(Map<String,Object>)m.get("capture_evidence");
            require("post_encoding_form_pair_history".equals(proof.get("mode")),"original scoped historical mode");
            no(proof,"grants_action_authority");no(proof,"business_completion_verified");yes(proof,"fresh_action_validation_required");
        }else require(number(m,"new_png_files")==0,"rejected graph never publishes pixels");
        require(m.get("diagnostic") instanceof Map,"actual nonempty Ctrip diagnostic");
        Map<String,Object> diag=(Map<String,Object>)m.get("diagnostic");
        require(new JSONObject(diag).toString(2).getBytes(StandardCharsets.UTF_8).length<=4096,"bounded actual pipeline diagnostic");
        if("untyped_with_content_during_encoding".equals(scenario)){
            require(number(m,"full_reads")==4&&number(m,"events")==2&&number(m,"content_events")==1
                    &&number(m,"unknown_events")==0&&number(m,"boundary_events")==0,
                    "actual complete saved C plus one typed and one legacy event");
            Map<String,Object> outer=(Map<String,Object>)diag.get("last_outer");
            require("saved_complete".equals(outer.get("stage"))&&"SKIPPED_OUTER".equals(outer.get("helper")),
                    "untyped increment cannot enter scoped form helper");
            require(Arrays.asList(1,0,-1).equals(outer.get("event_checks"))&&number(diag,"helper_records")==0,
                    "original onlyContentSince capture watermark refuses before helper");
        }
        return m;
    }
    public static void main(String[] args)throws Exception{
        run("archive_complete_pair_original_classifier_counterfactual",()->pair(false));
        run("coherent_closed_bfs_actual_adapter_and_original_classifier",()->{
            Map<String,Object> out=pair(true);
            for(boolean after:new boolean[]{false,true}){
                Map<String,Object> actual=derived(after);
                for(String key:Arrays.asList("all_non_label_ref_facts_unchanged","original_raw_nodes_not_modified","all_references_closed","signatures_nonempty"))yes(actual,key);
                require(number(actual,"nested_refresh_or_child_io")==0&&number(actual,"effects")==0,"labels use immutable facts only");
                require(number(actual,"references_obtained")==number(actual,"references_recycled"),"all copied real NodeRef ports released");
                out.put(after?"after_adapter":"before_adapter",actual);
            }return out;
        });
        run("closed_bfs_missing_fact_refused",()->{
            boolean refused=false;String reason=null;
            try{CapturedCtripLabelHost.derive(original(false),"0/0/7/0");}
            catch(IllegalStateException expected){refused=true;reason=expected.getMessage();}
            require(refused,"missing complete BFS fact cannot derive labels");
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("refused",refused);out.put("reason",reason);return out;
        });
        for(String kind:Arrays.asList("protected_date","query_capability","missing_child","interactive_recommendation","overlap_form","window_changed")){
            final String mutation=kind;run("original_full_classifier_refuses_"+kind,()->refusePair(mutation));
        }
        for(String scenario:Arrays.asList("ordinary_complete_pair","unknown_during_encoding","boundary_during_encoding",
                "untyped_during_encoding","protected_form_change","late_event_during_helper_snapshot","late_event_after_persist",
                "late_event_before_publication","deadline_during_census","cancel_during_census")){
            final String s=scenario;run("actual_observer_"+s,()->{
                if(!"untyped_during_encoding".equals(s))return pipeline(s);
                Map<String,Object> controls=new LinkedHashMap<String,Object>();
                controls.put("legacy_window_only_control",pipeline(s));
                controls.put("complete_content_refusal",pipeline("untyped_with_content_during_encoding"));
                return controls;
            });
        }
        for(String scenario:Arrays.asList("read_authority","frozen_window","ordinary_identity","installed_target","clock",
                "snapshot_build","classifier_rejected","accepted")){
            final String s=scenario;run("actual_helper_diagnostic_"+s,()->ObserverPipelineHost.exerciseCtripHelper(s));
        }
        for(String scenario:Arrays.asList("supported","personal","wrong_version","wrong_apk","wrong_package","wrong_goal",
                "owner_changed","unowned_background","missing_census","missing_windows","missing_budget","budget_expired")){
            final String s=scenario;run("captured_ctrip_opt_in_"+s,()->ObserverPipelineHost.exerciseCtripOptIn(s));
        }
        for(String scenario:Arrays.asList("complete_refusal_survives_precheck_and_deadline","max_valid_utf8_long_counters",
                "sdk_first_last_omitted_and_freeze","invalid_reference_and_oversize_rejected")){
            final String s=scenario;run("bounded_diagnostic_"+s,()->ObserverPipelineHost.exerciseCtripDiagnostic(s));
        }
        boolean pass=true;List<String> names=new ArrayList<String>();
        for(Map<String,Object> result:results){pass&=Boolean.TRUE.equals(result.get("pass"));names.add((String)result.get("name"));}
        require(new HashSet<String>(names).size()==names.size(),"all test names unique");
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("all_pass",pass);report.put("cases",results.size());
        report.put("assertions",assertions);report.put("case_names",names);report.put("results",results);
        report.put("phone_operations",0);report.put("historical_events_or_authority_reconstructed",false);
        report.put("android_bfs_execution_claimed",false);report.put("business_success_claimed",false);
        Files.write(Paths.get(args[0]),(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(new JSONObject(Collections.singletonMap("all_pass",pass)).toString());
        if(!pass)System.exit(1);
    }
}
