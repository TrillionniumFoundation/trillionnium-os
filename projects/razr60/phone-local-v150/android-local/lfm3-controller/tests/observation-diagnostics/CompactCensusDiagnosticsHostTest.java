package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual copied-census tracker plus actual Service terminal serializer.
 * Graphs and clocks are explicit host values; no phone frame or effect exists. */
final class CompactCensusDiagnosticsHostTest {
    private static int assertions;
    private static final List<String> names=new ArrayList<String>();
    private interface Case {void run()throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void test(String name,Case body)throws Exception{check(!names.contains(name),"unique case");body.run();names.add(name);System.out.println("PASS "+name);}
    private static String hash(String value)throws Exception{
        byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder out=new StringBuilder();
        for(byte b:bytes)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static ObservationDiagnostics.CensusStamp stamp(DiagnosticGraphHost.Graph graph){
        ObservationDiagnostics.CensusStamp s=DiagnosticGraphHost.fullStamp(graph);check(s!=null,"actual adapter accepted complete explicit host values");return s;
    }
    private static ObservationDiagnostics trace(ObservationDiagnostics.CensusStamp a,ObservationDiagnostics.CensusStamp b){
        ObservationDiagnostics d=DiagnosticGraphHost.tracker();d.phase("sample_graph",1000);
        for(int i=0;i<7;i++)d.note(ObservationDiagnostics.Event.EVENT_TARGET);d.note(ObservationDiagnostics.Event.EVENT_UNKNOWN);
        d.fullGraphChange("screenshot_graph",a,b,1200);d.finish("failed",1300);return d;
    }
    private static JSONObject wire(ObservationDiagnostics d)throws Exception{
        String raw=ObserverPipelineHost.actualSnapshot(d).call();JSONObject j=new JSONObject(raw);
        check(raw.getBytes(StandardCharsets.UTF_8).length<=16384&&j.toString(2).getBytes(StandardCharsets.UTF_8).length<=16384,"original compact and pretty 16KiB limits");
        check(j.getLong("deadline_elapsed_ms")==13000&&!j.getBoolean("changes_deadline")&&!j.getBoolean("grants_action_authority"),"original deadline and authority remain unchanged");
        JSONObject row=j.getJSONObject("last_native_full_graph_change");
        check(!row.getBoolean("node_text_recorded")&&!row.getBoolean("screenshot_pixels_recorded")&&!row.getBoolean("grants_publication")&&!row.getBoolean("grants_action_authority")&&!row.getBoolean("business_verified"),"diagnostics remain nonauthoritative and content reduced");
        if(row.has("compact_node_differences")){
            int total=row.getInt("changed_path_count"),kept=row.getInt("compact_retained_count");
            check(kept==row.getJSONArray("compact_node_differences").length()&&kept<=64&&kept>=0,"bounded retained rows");
            check(total==kept+row.getInt("compact_omitted_count")&&row.getBoolean("compact_truncated")== (kept<total),"honest complete count and omitted status");
            check(row.getInt("node_difference_limit")==8&&row.getInt("retained_detail_count")<=8,"original detailed row limit unchanged");
        }
        return j;
    }
    private static JSONObject delta(ObservationDiagnostics d)throws Exception{return wire(d).getJSONObject("last_native_full_graph_change");}
    private static ObservationDiagnostics.CensusStamp deep(boolean changed){
        ObservationDiagnostics.CensusStamp reference=stamp(DiagnosticGraphHost.fullGraph(2));List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();String path="0";
        for(int i=0;i<120;i++){
            Map<String,Object> row=new LinkedHashMap<String,Object>(reference.nodes.get("0"));row.put("path",path);row.put("parent_class",i==0?"":"android.widget.FrameLayout");
            row.put("class","android.widget.FrameLayout");row.put("children",i==119?0:1);row.put("text",changed&&i==119?"new":"");row.put("description","");row.put("label",null);values.add(row);path+="/0";
        }
        return new ObservationDiagnostics.CensusStamp(reference.identity,reference.appTree,reference.state,reference.window,values.size(),values);
    }
    private static ObservationDiagnostics.CensusStamp regrouped(){
        ObservationDiagnostics.CensusStamp reference=stamp(DiagnosticGraphHost.fullGraph(1536));List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();
        Map<String,Object> root=new LinkedHashMap<String,Object>(reference.nodes.get("0"));root.put("children",128);values.add(root);
        for(int i=0;i<128;i++){
            Map<String,Object> parent=new LinkedHashMap<String,Object>(reference.nodes.get("0/0"));parent.put("path","0/"+i);parent.put("class","android.widget.FrameLayout");parent.put("children",10);values.add(parent);
            for(int k=0;k<10;k++){
                Map<String,Object> leaf=new LinkedHashMap<String,Object>(reference.nodes.get("0/0"));leaf.put("path","0/"+i+"/"+k);leaf.put("parent_class","android.widget.FrameLayout");values.add(leaf);
            }
        }
        return new ObservationDiagnostics.CensusStamp(reference.identity,reference.appTree,reference.state,reference.window,values.size(),values);
    }
    private static void noise(ObservationDiagnostics d){
        for(int i=0;i<40;i++){d.phase(i%2==0?"sample_graph":"sample_gap",1000+i);d.graph("sample_graph",DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,false,1000+i);}
        List<ObservationDiagnostics.NodeStamp> a=new ArrayList<ObservationDiagnostics.NodeStamp>(),b=new ArrayList<ObservationDiagnostics.NodeStamp>();
        for(int i=0;i<8;i++){
            a.add(new ObservationDiagnostics.NodeStamp("n"+i,"0/"+i,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,0,0,100,100));
            b.add(new ObservationDiagnostics.NodeStamp("n"+i,"0/"+i,DiagnosticChecks.repeat('b',64),DiagnosticChecks.OWNER,1,0,101,100));
        }
        ObservationDiagnostics.GraphStamp old=new ObservationDiagnostics.GraphStamp(DiagnosticChecks.APP,DiagnosticChecks.GENERATION,DiagnosticChecks.OWNER,9,71,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,false,a);
        ObservationDiagnostics.GraphStamp fresh=new ObservationDiagnostics.GraphStamp(DiagnosticChecks.APP,DiagnosticChecks.GENERATION,DiagnosticChecks.OWNER,9,71,DiagnosticChecks.repeat('b',64),DiagnosticChecks.OWNER,DiagnosticChecks.OWNER,false,b);
        d.sampleGraphChange(old,1100);d.sampleGraphChange(fresh,1110);d.savedGraphChange(old,fresh,true,true,false,1120);
    }
    public static void main(String[] args)throws Exception{
        test("ten_geometry_changes_retain_all_compact_paths_and_exact_bounds",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(12),b=DiagnosticGraphHost.fullGraph(12);
            for(int i=1;i<=10;i++)DiagnosticGraphHost.change(b,i,"bounds",Arrays.asList(i,2,1000,2390));
            JSONObject row=delta(trace(stamp(a),stamp(b)));check(row.getInt("changed_path_count")==10&&row.getInt("compact_retained_count")==10&&!row.getBoolean("compact_truncated"),"ten synthetic geometry changes fit without omission");
            JSONArray rows=row.getJSONArray("compact_node_differences");TreeSet<String> paths=new TreeSet<String>();
            for(int i=0;i<rows.length();i++){JSONObject r=rows.getJSONObject(i);paths.add(r.getString("native_path"));check(r.getJSONArray("changed_fields").toString().equals("[\"bounds\"]"),"only actual changed field");int index=Integer.parseInt(r.getString("native_path").substring(2));check(r.getJSONArray("after_bounds").getInt(0)==index+1&&!r.has("changed_text_sha256"),"exact numeric geometry; unchanged text not duplicated");}
            for(int i=0;i<10;i++)check(paths.contains("0/"+i),"all ten independent expected paths");
        });
        test("busy_record_keeps_events_phases_and_reports_compact_omissions",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(12),b=DiagnosticGraphHost.fullGraph(12);for(int i=1;i<=10;i++)DiagnosticGraphHost.change(b,i,"bounds",Arrays.asList(i,2,1000,2390));
            ObservationDiagnostics d=DiagnosticGraphHost.tracker();noise(d);d.note(ObservationDiagnostics.Event.EVENT_TARGET);d.note(ObservationDiagnostics.Event.EVENT_UNKNOWN);d.fullGraphChange("screenshot_graph",stamp(a),stamp(b),1200);d.finish("failed",1300);
            JSONObject j=wire(d),row=j.getJSONObject("last_native_full_graph_change");check(row.getInt("changed_path_count")==10&&row.getInt("compact_retained_count")>2,"more compact changes retained than two full details");
            check(j.getJSONObject("events").getInt("EVENT_TARGET")==1&&j.getJSONObject("events").getInt("EVENT_UNKNOWN")==1&&j.getInt("transition_count")==40&&j.getInt("graph_record_count")==40,"event and sampling history preserved");
            check((j.has("last_native_sample_graph_change")||j.optBoolean("native_sample_graph_detail_omitted_for_budget"))&&j.getJSONArray("last_transitions").length()==16&&j.getJSONArray("last_graphs").length()==6,"original history limits and explicit detail-budget omission preserved");
        });
        test("added_and_removed_paths_keep_presence_type_and_complete_counts",()->{
            for(boolean add:new boolean[]{true,false}){
                JSONObject row=delta(trace(stamp(DiagnosticGraphHost.fullGraph(add?3:4)),stamp(DiagnosticGraphHost.fullGraph(add?4:3))));JSONArray rows=row.getJSONArray("compact_node_differences");
                check(row.getInt("changed_path_count")==2&&rows.length()==2,"changed root plus presence change");JSONObject p=null;for(int i=0;i<rows.length();i++)if(rows.getJSONObject(i).getString("native_path").equals("0/2"))p=rows.getJSONObject(i);
                check(p!=null&&p.getString("change_type").equals(add?"added":"removed"),"presence reason retained");check(p.isNull(add?"before_bounds":"after_bounds"),"missing side not invented");
            }
        });
        test("text_description_label_changes_record_only_full_UTF8_hashes",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);String value="私密内容🙂";
            for(String field:Arrays.asList("text","description","label"))DiagnosticGraphHost.change(b,1,field,value+field);
            JSONObject row=delta(trace(stamp(a),stamp(b))),compact=row.getJSONArray("compact_node_differences").getJSONObject(0),hashes=compact.getJSONObject("changed_text_sha256");
            for(String field:Arrays.asList("text","description","label"))check(hashes.getJSONObject(field).getString("after").equals(hash(value+field)),"independent UTF8 SHA256 "+field);
            check(!row.toString().contains(value)&&!row.toString().contains("PRIVATE_BODY")&&!compact.has("before_bounds")&&!compact.has("after_bounds"),"no raw content or unchanged coordinates");
        });
        test("nullable_label_is_distinguished_from_empty_text_hash",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);DiagnosticGraphHost.change(a,1,"label",null);DiagnosticGraphHost.change(b,1,"label","");
            JSONObject h=delta(trace(stamp(a),stamp(b))).getJSONArray("compact_node_differences").getJSONObject(0).getJSONObject("changed_text_sha256").getJSONObject("label");
            check(h.isNull("before")&&h.getString("after").equals(hash("")),"null and empty are distinct");
        });
        test("structural_and_capability_field_names_never_claim_harmless_motion",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);DiagnosticGraphHost.change(b,1,"clickable",true);DiagnosticGraphHost.change(b,1,"action_click",true);DiagnosticGraphHost.change(b,1,"view_id","opaque.changed.id");
            JSONObject r=delta(trace(stamp(a),stamp(b))).getJSONArray("compact_node_differences").getJSONObject(0);String fields=r.getJSONArray("changed_fields").toString();
            check(fields.contains("clickable")&&fields.contains("action_click")&&fields.contains("view_id")&&!r.toString().contains("opaque.changed.id")&&!r.has("harmless"),"named differences only; no classifier claim");
        });
        test("equal_full_censuses_record_zero_and_no_false_truncation",()->{
            ObservationDiagnostics.CensusStamp a=stamp(DiagnosticGraphHost.fullGraph(3));JSONObject row=delta(trace(a,a));check(row.getInt("changed_path_count")==0&&row.getInt("compact_retained_count")==0&&row.getInt("compact_omitted_count")==0&&!row.getBoolean("compact_truncated"),"zero is observed equality only");
        });
        test("unavailable_census_does_not_acquire_compact_or_zero_difference_proof",()->{
            JSONObject row=delta(trace(null,stamp(DiagnosticGraphHost.fullGraph(3))));check(row.getString("status").equals("full_census_unavailable")&&!row.getBoolean("full_census_compared")&&!row.has("compact_node_differences")&&!row.has("changed_path_count"),"unknown stays unknown");
        });
        test("identity_mismatch_cannot_merge_compact_paths",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(3),b=DiagnosticGraphHost.fullGraph(3);b.nativeActionTaskId=DiagnosticChecks.repeat('4',32);
            JSONObject row=delta(trace(stamp(a),stamp(b)));check(row.getString("status").equals("identity_mismatch")&&!row.getBoolean("full_census_compared")&&!row.has("compact_node_differences"),"cross-task rows not joined");
        });
        test("maximum_1536_changed_nodes_count_all_and_bound_both_encodings",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(1536),b=DiagnosticGraphHost.fullGraph(1536);for(int i=0;i<1536;i++)DiagnosticGraphHost.change(b,i,"text","x");
            JSONObject row=delta(trace(stamp(a),stamp(b)));check(row.getInt("changed_path_count")==1536&&row.getInt("compact_retained_count")>0&&row.getInt("compact_retained_count")<64&&row.getBoolean("compact_truncated")&&row.getBoolean("compact_omitted_for_budget"),"full count survives explicit bounded summary");
        });
        test("complete_old_fresh_union_can_exceed_each_census_node_limit",()->{
            JSONObject row=delta(trace(stamp(DiagnosticGraphHost.fullGraph(1536)),regrouped()));check(row.getInt("changed_path_count")==2816&&row.getInt("compact_omitted_count")==2816-row.getInt("compact_retained_count"),"add/remove union not capped at one tree size");
        });
        test("many_fields_long_unicode_content_and_identifiers_stay_bounded",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(10),b=DiagnosticGraphHost.fullGraph(10);
            for(int i=1;i<10;i++){
                DiagnosticGraphHost.change(b,i,"view_id",DiagnosticChecks.repeat('v',256));DiagnosticGraphHost.change(b,i,"class",DiagnosticChecks.repeat('c',128));
                DiagnosticGraphHost.change(b,i,"text",DiagnosticChecks.repeat('私',1024));DiagnosticGraphHost.change(b,i,"description",DiagnosticChecks.repeat('密',1024));DiagnosticGraphHost.change(b,i,"label",DiagnosticChecks.repeat('秘',4096));
                DiagnosticGraphHost.change(b,i,"scroll_actions",DiagnosticChecks.repeat('s',1024));DiagnosticGraphHost.change(b,i,"ime_enter",DiagnosticChecks.repeat('i',512));
                for(String flag:Arrays.asList("clickable","action_click","focused","editable","selected","checkable","checked","password","scrollable"))DiagnosticGraphHost.change(b,i,flag,true);
                DiagnosticGraphHost.change(b,i,"ref_signature_sha256",DiagnosticChecks.repeat('b',64));DiagnosticGraphHost.change(b,i,"input_sha256",DiagnosticChecks.repeat('b',64));
            }
            JSONObject row=delta(trace(stamp(a),stamp(b)));check(row.getInt("changed_path_count")==9&&!row.toString().contains("私")&&!row.toString().contains("密")&&!row.toString().contains("秘"),"wide changed fields still redact all content");
        });
        test("maximum_diagnostic_path_length_remains_exact_without_new_reader",()->{
            JSONObject row=delta(trace(deep(false),deep(true)));String path=row.getJSONArray("compact_node_differences").getJSONObject(0).getString("native_path");check(path.length()==239&&row.getInt("changed_path_count")==1,"exact bounded carrier path, no new collection");
        });
        test("terminal_budget_pruning_never_mutates_original_compact_rows",()->{
            DiagnosticGraphHost.Graph a=DiagnosticGraphHost.fullGraph(100),b=DiagnosticGraphHost.fullGraph(100);for(int i=1;i<100;i++)DiagnosticGraphHost.change(b,i,"text","new");
            ObservationDiagnostics d=trace(stamp(a),stamp(b));JSONObject original=new JSONObject(d.snapshot(1300)).getJSONObject("last_native_full_graph_change");
            check(original.getInt("compact_retained_count")==64&&!original.getBoolean("compact_omitted_for_budget"),"bounded immutable source retains first64");JSONObject trimmed=delta(d);
            JSONObject after=new JSONObject(d.snapshot(99999)).getJSONObject("last_native_full_graph_change");check(original.toString().equals(after.toString())&&trimmed.getInt("compact_retained_count")<64,"only terminal serialization copy pruned");
        });
        test("terminal_record_is_frozen_and_does_not_prove_worker_drain",()->{
            ObservationDiagnostics d=trace(stamp(DiagnosticGraphHost.fullGraph(3)),stamp(DiagnosticGraphHost.fullGraph(4)));String original=ObserverPipelineHost.actualSnapshot(d).call();
            d.fullGraphChange("saved_graph",null,null,99999);d.note(ObservationDiagnostics.Event.PUBLISHED);d.worker(false);
            check(original.equals(ObserverPipelineHost.actualSnapshot(d).call()),"late diagnosis cannot mutate terminal values");JSONObject j=wire(d);check(!j.getBoolean("worker_drained_proved_by_this_record"),"diagnostic remains separate from cleanup authority");
        });
        JSONObject result=new JSONObject().put("schema","hepta.compact-census-diagnostics-host.v1").put("all_pass",true).put("cases",names.size()).put("assertions",assertions).put("case_names",names)
                .put("actual_tracker_and_Service_snapshot",true).put("deadline_or_sampling_changed",false).put("android_execution",false).put("phone_operations",0).put("business_completion_verified",false);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
