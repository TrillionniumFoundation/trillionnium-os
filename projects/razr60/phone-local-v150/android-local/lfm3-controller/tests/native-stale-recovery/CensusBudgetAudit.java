package org.trillionnium.hepta.local;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Public, synthetic boundary fixture. No captured phone text or paths. */
@SuppressWarnings("try")
public final class CensusBudgetAudit {
    static final String TASK="0123456789abcdef0123456789abcdef",GEN="01234567-89ab-cdef-0123-456789abcdef";
    static final String MARK="CENSUS_PRIVATE_SENTINEL_",PKG="ctrip.android.view";
    static final int LEAVES=64,MAX=262144;
    static int assertions;
    static void check(boolean v,String why){assertions++;if(!v)throw new AssertionError(why);}
    static String repeat(String s,int n){StringBuilder b=new StringBuilder();while(n-->0)b.append(s);return b.toString();}
    static String id(int n){return String.format(Locale.ROOT,"%032x",n);}
    static String h(String s){return NativeActionSnapshotCheck.hash(s);}
    static int size(String s){return s.getBytes(StandardCharsets.UTF_8).length;}
    static Map<String,Object> map(){return new TreeMap<String,Object>();}
    static Map<String,Object> node(String path,String parent,String cls,int children,List<Integer> bounds){
        Map<String,Object> n=map();n.put("path",path);n.put("parent_class",parent);n.put("package",PKG);n.put("window_id",17);
        n.put("class",cls);n.put("view_id","");n.put("text","");n.put("description","");n.put("label","");
        n.put("ref_signature_sha256",h("reference"));n.put("input_sha256",null);n.put("bounds",bounds);n.put("children",children);
        for(String k:Arrays.asList("visible","enabled"))n.put(k,true);
        for(String k:Arrays.asList("clickable","editable","scrollable","focused","password","selected","checkable","checked","action_click"))n.put(k,false);
        n.put("scroll_actions","");n.put("ime_enter","");return n;
    }
    static NativeActionSnapshotCheck.Snapshot snapshot(int padding,int extra,boolean fresh,int ordinal){
        List<Map<String,Object>> raw=new ArrayList<Map<String,Object>>();
        List<Integer> rootBounds=Arrays.asList(0,0,1224,2992);
        raw.add(node("0","","android.widget.FrameLayout",fresh?3:2,rootBounds));
        Map<String,Object> pager=node("0/0","android.widget.FrameLayout","androidx.viewpager.widget.ViewPager",5,Arrays.asList(0,80,1224,280));pager.put("scrollable",true);raw.add(pager);
        for(int x=0;x<5;x++){
            Map<String,Object> tile=node("0/0/"+x,"androidx.viewpager.widget.ViewPager","android.view.ViewGroup",0,Arrays.asList(10+x*220,100,200+x*220,220));
            tile.put("view_id",NativeActionSnapshotCheck.CP+NativeActionSnapshotCheck.TILE_IDS[x]);tile.put("clickable",true);tile.put("action_click",true);raw.add(tile);
        }
        raw.add(node("0/1","android.widget.FrameLayout","android.widget.FrameLayout",LEAVES,Arrays.asList(0,350,1224,2000)));
        for(int x=0;x<LEAVES;x++){
            Map<String,Object> leaf=node("0/1/"+x,"android.widget.FrameLayout","android.widget.TextView",0,Arrays.asList(20,400+x*20,1200,415+x*20));
            int count=padding/LEAVES+(x<padding%LEAVES?1:0);leaf.put("label",MARK+repeat("q",count));raw.add(leaf);
        }
        if(fresh){Map<String,Object> banner=node("0/2","android.widget.FrameLayout","android.view.View",0,Arrays.asList(0,2400,1224,2500));banner.put("label",repeat("z",extra));raw.add(banner);}
        Map<String,Object> env=map();
        env.put("task_id",TASK);env.put("origin_observation_id",id(100+ordinal));env.put("background_generation",GEN);
        for(String k:Arrays.asList("owner_sha256","target_sha256","authorization_sha256","selection_sha256","installed_set_sha256","goal_sha256","window_metadata_sha256","reported_windows_sha256"))env.put(k,h(k));
        env.put("package",PKG);env.put("display_id",2);env.put("window_id",17);env.put("rotation",0);env.put("width",1224);env.put("height",2992);env.put("root_bounds",rootBounds);
        env.put("reported_windows_complete",true);env.put("ime_visibility","hidden");env.put("captured_elapsed_ms",fresh?1020L:1000L);env.put("full_native_complete",true);env.put("visited",raw.size());
        for(String k:Arrays.asList("pending","node_omissions","text_omissions","child_omissions"))env.put(k,0);
        List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>();for(Map<String,Object> n:raw)nodes.add(new NativeActionSnapshotCheck.Node(n));
        return new NativeActionSnapshotCheck.Snapshot(env,nodes);
    }
    static Map<String,Object> diagnostic(int padding,int extra,int ordinal){
        NativeActionSnapshotCheck.Snapshot old=snapshot(padding,extra,false,ordinal),fresh=snapshot(padding,extra,true,ordinal);
        Map<String,Object> identity=map();for(String key:NativeActionSnapshotCheck.IDENTITY)identity.put(key,old.env.get(key));
        NativeActionSnapshotCheck.Intent intent=new NativeActionSnapshotCheck.Intent(NativeActionSnapshotCheck.OPEN,PKG,"0/0/1","",h("reference"),id(200+ordinal),"n12",h("action"),null,identity,1010,8000);
        String refused=null;try{NativeActionSnapshotCheck.compare(intent,old,fresh,1030);}catch(IllegalArgumentException expected){refused=expected.getMessage();}
        check("actual ancestor changed: 0".equals(refused),"actual unchanged ancestor guard must reject the added root branch: "+refused);
        return NativeActionSnapshotCheck.rejectionEvidence(intent,old,fresh,1030,id(300+ordinal),h("screen"),h("frame"),refused);
    }
    static int measured(int padding,int extra){try{return size(new JSONObject(diagnostic(padding,extra,1)).toString());}catch(IllegalArgumentException bound){
        if(!"complete rejection diagnostic byte budget".equals(bound.getMessage()))throw bound;return Integer.MAX_VALUE;}}
    static ActionExecutionState state(int ordinal){
        final long[] now={1100};ActionExecutionState s=new ActionExecutionState(id(300+ordinal),TASK,id(200+ordinal),id(100+ordinal),h("authorization_sha256"),17,2,GEN,1100,8000,new ActionExecutionState.Clock(){public long elapsedRealtime(){return now[0];}});
        s.phase("worker_started");now[0]=1200;s.drained();now[0]=1201;check(s.publish(false,true),"synthetic worker publication");return s;
    }
    static JSONObject receipt(int step,JSONObject execution)throws Exception {
        return new JSONObject().put("action",new JSONObject().put("action","click").put("observation_id",id(100+step)).put("package",PKG).put("node_id","n12").put("node_label",""))
            .put("accepted",false).put("done_success_eligible",false).put("dispatched",false).put("stale",true).put("detail","原生目的复核失败: actual ancestor changed: 0")
            .put("model_run_id",id(200+step)).put("model_issued",true).put("task_phase",new JSONObject())
            .put("qualification_scope",JSONObject.NULL).put("task_authorization_sha256",h("authorization_sha256"))
            .put("task_authorization",JSONObject.NULL).put("background_session",JSONObject.NULL).put("ime_submit",JSONObject.NULL).put("fixed_intent",JSONObject.NULL)
            .put("action_execution",execution);
    }
    static JSONObject terminal(JSONArray projected,JSONObject last,boolean large)throws Exception {
        JSONObject result=SessionTerminalHost.result("failed",false,false,true);
        JSONObject completion=result.getJSONObject("completion_evidence");
        if(!large)completion.remove("native_app_session");
        completion.put("audit_scalar_execution_projections",projected);
        result.put("steps",20).put("last_action_execution",last);
        return result;
    }
    public static void main(String[] args)throws Exception {
        Path root=Paths.get(args[0]);Files.createDirectory(root);Files.createDirectory(root.resolve("actions"));
        int low=0,high=LEAVES*(4096-MARK.length());
        while(low<high){int mid=(low+high+1)/2;if(measured(mid,0)<=MAX)low=mid;else high=mid-1;}
        int extra=measured(low,1)<=MAX?1:0;
        check(measured(low,extra)==MAX,"fixture must reach the exact actual compact JSON cap");
        List<Map<String,Object>> historyRows=new ArrayList<Map<String,Object>>();JSONArray projected=new JSONArray();
        CensusProjectionBridge bridge=new CensusProjectionBridge();JSONArray actionStats=new JSONArray();
        long compactSum=0,prettySum=0;int largestPretty=0;JSONObject last=null;
        for(int step=1;step<=20;step++){
            String census=new JSONObject(diagnostic(low,extra,step)).toString();check(size(census)==MAX,"max-size census "+step);
            ActionExecutionState state=state(step);JSONObject raw=CensusProjectionBridge.diagnostic(state,census);
            JSONObject baseline=CensusProjectionBridge.diagnostic(state,null);
            Map<String,Object> projection=CensusProjectionBridge.project(raw),without=CensusProjectionBridge.project(baseline);
            check(new JSONObject(projection).similar(new JSONObject(without)),"census must have exactly zero projected contribution");
            check(!new JSONObject(projection).toString().contains(MARK),"private node label crossed projection");
            projected.put(new JSONObject(projection));
            JSONObject row=CensusProjectionBridge.staleHistory(step);historyRows.add(CensusProjectionBridge.fields(row));
            // Readable history must reject an accidental nested census rather than admit it.
            Map<String,Object> poisoned=new LinkedHashMap<String,Object>(CensusProjectionBridge.fields(row));poisoned.put("native_action_rejection_census",new JSONObject(census));
            boolean refused=false;try{RecentActionProjection.readableEvents(Collections.singletonList(poisoned));}catch(IllegalArgumentException expected){refused=true;}
            check(refused,"history nested-diagnostic negative control");
            byte[] action=receipt(step,raw).toString(2).getBytes(StandardCharsets.UTF_8);
            byte[] small=receipt(step,baseline).toString(2).getBytes(StandardCharsets.UTF_8);
            Path file=root.resolve("actions").resolve(String.format(Locale.ROOT,"step-%02d-action.json",step));SessionTerminalHost.write(file,action);
            check(Arrays.equals(action,Files.readAllBytes(file)),"actual pretty evidence write");
            compactSum+=size(census);prettySum+=action.length;largestPretty=Math.max(largestPretty,action.length);
            actionStats.put(new JSONObject().put("step",step).put("compact_census_bytes",size(census)).put("pretty_action_bytes",action.length).put("pretty_action_without_census_bytes",small.length).put("added_pretty_bytes",action.length-small.length).put("sha256",SessionTerminalHost.sha(action)));
            bridge.lastActionExecution=state;last=bridge.actionExecutionEvidence(TASK);
            check(!last.has("native_action_rejection_census")&&!last.toString().contains(MARK),"actual final service evidence must omit ActionWork attachment");
        }
        RecentActionProjection.ReadableEvents events=RecentActionProjection.readableEvents(historyRows);
        JSONObject data=new JSONObject().put("action_schema","phone.v3").put("events",new JSONArray(events.rows)).put("screen",new JSONObject().put("package",PKG).put("observation_id",id(121)));
        String prompt="UNTRUSTED_DATA\n"+CensusProjectionBridge.prompt(data).replace("<","\\u003c")+"\nOWNER\n公开合成边界测试";
        check(!prompt.contains(MARK)&&!prompt.contains("native_action_rejection_census")&&!prompt.contains("complete_two_censuses"),"prompt census absence");
        SessionTerminalHost.write(root.resolve("prompt.txt"),prompt.getBytes(StandardCharsets.UTF_8));
        SessionTerminalHost.root=root.resolve("terminal");Files.createDirectory(SessionTerminalHost.root);
        JSONArray terminals=new JSONArray();
        for(boolean large:new boolean[]{false,true}){
            JSONObject result=terminal(projected,last,large);check(!result.toString().contains(MARK)&&!result.toString().contains("native_action_rejection_census"),"result census absence");
            try(SessionTerminalHost.Scenario s=new SessionTerminalHost.Scenario(large?"compact":"inline",result)){
                byte[] original=Files.readAllBytes(s.resultPath);s.complete();JSONObject journal=s.committed();byte[] committed=Files.readAllBytes(s.sessionPath);
                check(!s.session.isBlocked(),"real terminal writer blocked: "+s.session.log);
                check(Arrays.equals(original,Files.readAllBytes(s.resultPath)),"terminal must preserve full task bytes");
                check(original.length<SessionTerminalEvidence.MAX_RESULT_BYTES,"actual result remains under 8MiB");
                check(committed.length<=65536,"actual session remains under 64KiB");
                check(!new String(committed,StandardCharsets.UTF_8).contains(MARK),"session census absence");
                boolean reference=journal.has("task_result_reference");
                check(reference==large,"inline/compact path classification");
                check(!journal.getBoolean("completion_verified")&&!journal.getBoolean("model_reported_success"),"failed unverified status retained");
                terminals.put(new JSONObject().put("path",large?"compact_reference":"inline").put("result_bytes",original.length).put("result_sha256",SessionTerminalHost.sha(original)).put("session_bytes",committed.length).put("session_sha256",SessionTerminalHost.sha(committed)).put("compact_reference",reference).put("write_and_bind_verified",true).put("failed_and_unverified_preserved",true));
            }
        }
        JSONObject report=new JSONObject().put("schema","hepta.native-census-boundary-cases.v1").put("all_pass",true).put("synthetic_fixture",true).put("assertions",assertions)
            .put("diagnostic_count",20).put("compact_census_bytes_each",MAX).put("compact_census_bytes_total",compactSum).put("pretty_action_bytes_total",prettySum).put("largest_pretty_action_bytes",largestPretty)
            .put("pretty_file_includes_other_synthetic_receipt_fields",true).put("pretty_file_is_not_capped_to_256KiB",true).put("projection_census_added_bytes",0)
            .put("prompt_projection_bytes",size(prompt)).put("prompt_is_synthetic_screen_and_owner",true).put("prompt_census_absent",true).put("result_session_census_absent",true)
            .put("actual_unmodified_comparator_rejected_ancestor_changes",true).put("two_complete_censuses_created_by_production_helper",true)
            .put("history_rejects_nested_census",true).put("actions",actionStats).put("terminal_paths",terminals);
        System.out.println(report.toString());
    }
}
