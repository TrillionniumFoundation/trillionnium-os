package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Bounded non-authoritative values only: no Android object, I/O, sampling or effect. */
final class ObservationDiagnostics {
    static final int MAX_RECORDS=96,MAX_TRANSITIONS=16,MAX_FRAMES=6,MAX_NODE_DIFFS=8,MAX_NODES=512,MAX_JSON_BYTES=16384;
    enum Event {
        SAMPLE_START,SAMPLE_NO_ROOT,SAMPLE_STALE_ROOT,SAMPLE_ERROR,SAMPLE_EVENT_RESET,SAMPLE_EVENT_RECHECKED,
        SAMPLE_KEY_CHANGED,SAMPLE_MISSING,SAMPLE_READY,SAMPLE_WAIT,SAMPLE_EXPIRED,SAMPLE_CANCELLED,
        SCREENSHOT_INTERVAL_WAIT,CAPTURE_START,CAPTURE_CALLBACK_OK,CAPTURE_CALLBACK_FAIL,
        SCREENSHOT_GRAPH_MISSING,SCREENSHOT_GRAPH_STALE,SCREENSHOT_GRAPH_CHANGED,
        SAVED_GRAPH_MISSING,SAVED_GRAPH_STALE,SAVED_GRAPH_CHANGED,CAPTURE_EVENT_RESET,CAPTURE_EVENT_RECHECKED,
        CAPTURE_RETRY,INTERVAL_RETRY,PUBLISHED,EVENT_TARGET,EVENT_UNKNOWN,REQUEST_ERROR,WORKER_ABANDONED
    }
    private static final String[] PHASES={"queued","sample_graph","sample_gap","screenshot_callback",
        "screenshot_copy","screenshot_graph","png_encode","png_fsync","png_hash","saved_graph","publish","retry_gap"};
    final String taskId,requestId,ownerSha,packageName,generation;
    final int displayId,sequence;
    final long started,deadline;
    private final long[] counts=new long[Event.values().length];
    private final long[][] phases=new long[PHASES.length][3];
    private final List<Map<String,Object>> transitions=new ArrayList<Map<String,Object>>();
    private final List<Map<String,Object>> frames=new ArrayList<Map<String,Object>>();
    private int phase;
    private long phaseAt,lastClock,transitionTotal,frameTotal;
    private boolean ended,clockRegressed,workerActive;
    private String previousSampleKey,publishedObservationId,terminal;
    private GraphStamp capturedStamp,afterStamp;
    private String afterStage;
    private Map<String,Object> pairSeal,publication,lastMismatch;
    private long mismatchTotal;
    private Map<String,Object> lastSavedGraphChange,lastSeedDecision;private long seedAdmissions;
    private static final String[] SEAL_PREDICATES={"native_graph_rechecked","frozen_window_present","frozen_window_matches",
        "authorization_present","authorization_same","pair_events_same","pair_unknown_events_same","capture_unknown_events_same",
        "sample_start_after_request","sample_complete_after_start","sample_complete_before_capture","capture_before_callback",
        "callback_before_pair_start","pair_start_before_complete"};

    ObservationDiagnostics(String task,String request,String owner,String pkg,String generation,int display,int sequence,long started,long deadline){
        if(!id(task)||!id(request)||!sha(owner)||pkg==null||pkg.length()>128||!pkg.matches("[A-Za-z0-9_.]+")
                ||generation==null||!generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                ||display<0||sequence<1||sequence>MAX_RECORDS||started<0||deadline<started)throw new IllegalArgumentException("diagnostic identity unavailable");
        taskId=task;requestId=request;ownerSha=owner;packageName=pkg;this.generation=generation;
        displayId=display;this.sequence=sequence;this.started=started;this.deadline=deadline;phaseAt=started;lastClock=started;phases[0][0]=1;
    }
    static boolean id(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    static boolean sha(String s){return s!=null&&s.matches("[0-9a-f]{64}");}
    private static long plus(long a,long b){return b<0||Long.MAX_VALUE-a<b?Long.MAX_VALUE:a+b;}
    private long clock(long now){if(now<lastClock){clockRegressed=true;return lastClock;}lastClock=now;return now;}
    private void closePhase(long now){long elapsed=Math.max(0,now-phaseAt);phases[phase][1]=plus(phases[phase][1],elapsed);
        phases[phase][2]=Math.max(phases[phase][2],elapsed);phaseAt=now;}
    synchronized void phase(String name,long now){
        if(ended)return;int next=-1;for(int i=0;i<PHASES.length;i++)if(PHASES[i].equals(name)){next=i;break;}
        if(next<0)return;now=clock(now);closePhase(now);phase=next;phases[phase][0]=plus(phases[phase][0],1);
        Map<String,Object> row=map();row.put("phase",name);row.put("elapsed_ms",now-started);
        append(transitions,row,MAX_TRANSITIONS);transitionTotal=plus(transitionTotal,1);
    }
    synchronized void note(Event event){
        if(!ended&&event!=null){counts[event.ordinal()]=plus(counts[event.ordinal()],1);readMismatch(event);}
    }
    synchronized void worker(boolean active){if(!ended)workerActive=active;}
    synchronized void reset(){if(!ended){previousSampleKey=null;capturedStamp=null;afterStamp=null;afterStage=null;}}
    synchronized void graph(String stage,String key,String appTree,String state,String window,boolean truncated,long now){
        if(ended||!("sample_graph".equals(stage)||"screenshot_graph".equals(stage)||"saved_graph".equals(stage))
                ||!sha(key)||!sha(appTree)||!sha(state)||!sha(window))return;
        now=clock(now);
        if("sample_graph".equals(stage)){
            if(previousSampleKey!=null&&!previousSampleKey.equals(key))note(Event.SAMPLE_KEY_CHANGED);
            previousSampleKey=key;
        }
        Map<String,Object> row=map();row.put("stage",stage);row.put("elapsed_ms",now-started);
        row.put("frame_key_sha256",key);row.put("app_tree_sha256",appTree);
        row.put("observation_state_sha256",state);row.put("window_metadata_sha256",window);row.put("truncated",truncated);
        append(frames,row,MAX_FRAMES);frameTotal=plus(frameTotal,1);
    }
    /** Reuse bounded hashes already collected on the worker; never performs another read. */
    synchronized void savedGraphChange(GraphStamp before,GraphStamp after,boolean nativeComplete,
                                       boolean frozenWindow,boolean candidate,long now){
        if(ended)return;Map<String,Object> delta=difference(before,after,null);if(delta==null)return;
        delta.put("stage","saved_graph");delta.put("elapsed_ms",clock(now)-started);
        delta.put("native_observation_complete",nativeComplete);delta.put("frozen_window_available",frozenWindow);
        delta.put("seed_candidate",candidate);lastSavedGraphChange=Collections.unmodifiableMap(delta);
    }
    synchronized void seedDecision(String decision,long now){
        if(ended||!("admitted".equals(decision)||"discarded_before_admission".equals(decision)
                ||"invalidated_before_sample".equals(decision)||"replaced_by_sample".equals(decision)
                ||"ready".equals(decision)))return;
        Map<String,Object> row=map();row.put("decision",decision);row.put("elapsed_ms",clock(now)-started);
        row.put("grants_action_authority",false);lastSeedDecision=Collections.unmodifiableMap(row);
        if("admitted".equals(decision))seedAdmissions=plus(seedAdmissions,1);
    }
    synchronized void missingSample(){if(!ended){note(Event.SAMPLE_MISSING);previousSampleKey=null;}}
    /** References are immutable bounded values from reads which already occurred.
     * No Graph/Android object, new traversal, screenshot or authority is retained. */
    synchronized void capture(GraphStamp stamp){
        if(ended)return;capturedStamp=stamp;afterStamp=null;afterStage=null;pairSeal=null;publication=null;
    }
    synchronized void retained(String stage,GraphStamp stamp){
        if(ended||!("screenshot_graph".equals(stage)||"saved_graph".equals(stage)))return;
        afterStage=stage;afterStamp=stamp;
    }
    synchronized void beginSeal(long captureEvents,long captureUnknown,long pairEvents,long pairUnknown,boolean retry,boolean selected){
        if(ended)return;pairSeal=map();pairSeal.put("capture_events",captureEvents);pairSeal.put("capture_unknown_events",captureUnknown);
        pairSeal.put("pair_start_events",pairEvents);pairSeal.put("pair_start_unknown_events",pairUnknown);
        pairSeal.put("retry_before_seal",retry);pairSeal.put("native_recheck_selected",selected);pairSeal.put("seal_created",false);
        Map<String,Object> predicates=map();for(String name:SEAL_PREDICATES)predicates.put(name,null);pairSeal.put("predicates",predicates);
        pairSeal.put("predicate_null_means_not_evaluated",true);pairSeal.put("grants_action_authority",false);
    }
    static boolean sealPredicate(ObservationDiagnostics values,int index,boolean result){
        if(values!=null)values.recordSeal(index,result,null,null);return result;
    }
    static boolean sealCounter(ObservationDiagnostics values,int index,long expected,long observed){
        boolean result=expected==observed;if(values!=null)values.recordSeal(index,result,Long.valueOf(expected),Long.valueOf(observed));return result;
    }
    private synchronized void recordSeal(int index,boolean result,Long expected,Long observed){
        if(ended||pairSeal==null||index<0||index>=SEAL_PREDICATES.length)return;
        Object raw=pairSeal.get("predicates");if(!(raw instanceof Map<?,?>))return;
        Map<String,Object> predicates=map();for(String name:SEAL_PREDICATES)predicates.put(name,((Map<?,?>)raw).get(name));
        predicates.put(SEAL_PREDICATES[index],Boolean.valueOf(result));pairSeal.put("predicates",predicates);
        if(expected!=null){pairSeal.put(SEAL_PREDICATES[index]+"_expected",expected);pairSeal.put(SEAL_PREDICATES[index]+"_observed",observed);}
    }
    synchronized void sealCreated(){if(!ended&&pairSeal!=null)pairSeal.put("seal_created",true);}
    synchronized void publicationMode(boolean sealed,long events){
        if(ended)return;publication=map();publication.put("mode",sealed?"frozen_window_identity":"whole_observed_graph");
        publication.put("checked_event_watermark",events);publication.put("seal_created",sealed);publication.put("grants_action_authority",false);
    }
    synchronized void publicationDecision(boolean retry,boolean eventsChanged,boolean eventsRechecked,boolean currentCheck){
        if(ended||publication==null)return;publication.put("retry_after_existing_fence",retry);
        publication.put("events_changed",eventsChanged);publication.put("events_rechecked",eventsRechecked);
        publication.put("current_check",currentCheck);
    }
    private void readMismatch(Event event){
        final String stage;
        switch(event){
            case SCREENSHOT_GRAPH_MISSING:case SCREENSHOT_GRAPH_STALE:case SCREENSHOT_GRAPH_CHANGED:stage="screenshot_graph";break;
            case SAVED_GRAPH_MISSING:case SAVED_GRAPH_STALE:case SAVED_GRAPH_CHANGED:stage="saved_graph";break;
            default:return;
        }
        GraphStamp after=stage.equals(afterStage)?afterStamp:null;
        String reason=noncomparable(capturedStamp,after);
        Map<String,Object> row=map();row.put("mismatch_stage",stage);row.put("existing_event",event.name());
        row.put("same_identity_comparable",reason==null);row.put("noncomparable_reason",reason);
        Map<String,Object> diff=reason==null?difference(capturedStamp,after,null):null;
        row.put("graph_difference",diff);row.put("graph_difference_omitted_for_byte_limit",false);
        row.put("node_differences_truncated",diff==null?null:diff.get("node_differences_truncated"));
        row.put("selected_node_id",null);row.put("additional_graph_reads",0);row.put("additional_screenshots",0);
        row.put("grants_action_authority",false);lastMismatch=Collections.unmodifiableMap(row);mismatchTotal=plus(mismatchTotal,1);
    }
    private String noncomparable(GraphStamp before,GraphStamp after){
        if(before==null)return "captured_stamp_unavailable";if(after==null)return "after_stamp_unavailable";
        if(!packageName.equals(before.packageName)||!packageName.equals(after.packageName))return "package_identity_changed";
        if(!generation.equals(before.generation)||!generation.equals(after.generation))return "background_generation_changed";
        if(!ownerSha.equals(before.ownerSha)||!ownerSha.equals(after.ownerSha))return "owner_identity_changed";
        if(displayId!=before.displayId||displayId!=after.displayId)return "display_identity_changed";
        if(before.windowId!=after.windowId)return "window_identity_changed";return null;
    }
    /** Keep the original byte ceiling and all prior fields if the new optional
     * bounded difference would otherwise make a serialized record too large. */
    static Map<String,Object> withoutReadDifference(Map<String,Object> original){
        Map<String,Object> value=new LinkedHashMap<String,Object>(original);
        Object raw=value.get("last_read_mismatch");
        if(raw instanceof Map<?,?>){
            Map<String,Object> row=map();for(Map.Entry<?,?> entry:((Map<?,?>)raw).entrySet())
                if(entry.getKey() instanceof String)row.put((String)entry.getKey(),entry.getValue());
            if(row.get("graph_difference")!=null){row.put("graph_difference",null);row.put("graph_difference_omitted_for_byte_limit",true);}
            value.put("last_read_mismatch",row);
        }
        return value;
    }
    /** Preserve prior diagnostics while dropping only the optional second graph detail. */
    static Map<String,Object> withoutSavedGraphDifference(Map<String,Object> original){
        Map<String,Object> value=new LinkedHashMap<String,Object>(original);
        if(value.containsKey("last_native_saved_graph_change")){
            value.remove("last_native_saved_graph_change");
            value.put("native_saved_graph_detail_omitted_for_budget",true);
        }
        return value;
    }
    synchronized void published(String id,long now){if(!ended&&id(id)){publishedObservationId=id;note(Event.PUBLISHED);finish("published",now);}}
    synchronized void finish(String status,long now){
        if(ended)return;if(!"published".equals(status)&&!"failed".equals(status))return;
        now=clock(now);closePhase(now);terminal=status;ended=true;
        capturedStamp=null;afterStamp=null;afterStage=null;
    }
    synchronized Map<String,Object> snapshot(long now){
        long end=ended?lastClock:Math.max(lastClock,now);
        Map<String,Object> value=map();value.put("schema","hepta.observation-diagnostic.v1");
        value.put("task_id",taskId);value.put("request_id",requestId);value.put("owner_sha256",ownerSha);
        value.put("request_sequence",sequence);value.put("record_limit_per_task",MAX_RECORDS);value.put("record_byte_limit",MAX_JSON_BYTES);
        value.put("package",packageName);value.put("background_generation",generation);value.put("display_id",displayId);
        value.put("started_elapsed_ms",started);value.put("deadline_elapsed_ms",deadline);value.put("snapshot_elapsed_ms",end);
        value.put("elapsed_ms",Math.max(0,end-started));value.put("deadline_reached_at_snapshot",end>=deadline);
        value.put("request_terminal_observed",ended);value.put("terminal",terminal);value.put("phase",PHASES[phase]);
        value.put("clock_regressed",clockRegressed);value.put("worker_active_at_last_diagnostic_update",workerActive);
        value.put("diagnostic_updates_frozen_at_terminal",ended);
        value.put("worker_drained_proved_by_this_record",false);value.put("published_observation_id",publishedObservationId);
        Map<String,Object> events=map();for(Event e:Event.values())if(counts[e.ordinal()]!=0)events.put(e.name(),counts[e.ordinal()]);
        value.put("events",events);Map<String,Object> stages=map();
        for(int i=0;i<PHASES.length;i++)if(phases[i][0]!=0){
            long open=!ended&&i==phase?Math.max(0,end-phaseAt):0;Map<String,Object> row=map();
            row.put("count",phases[i][0]);row.put("total_ms",plus(phases[i][1],open));row.put("max_ms",Math.max(phases[i][2],open));stages.put(PHASES[i],row);
        }
        value.put("phases",stages);value.put("phase_times_are_elapsed_not_cpu",true);
        value.put("last_transitions",copyRows(transitions));value.put("transition_count",transitionTotal);
        value.put("transitions_truncated",transitionTotal>MAX_TRANSITIONS);value.put("transition_limit",MAX_TRANSITIONS);
        value.put("last_graphs",copyRows(frames));value.put("graph_record_count",frameTotal);
        value.put("graph_records_truncated",frameTotal>MAX_FRAMES);value.put("graph_record_limit",MAX_FRAMES);
        value.put("last_pair_seal",pairSeal==null?null:copyMap(pairSeal));
        value.put("last_publication_check",publication==null?null:copyMap(publication));
        value.put("last_read_mismatch",lastMismatch==null?null:copyMap(lastMismatch));
        value.put("read_mismatch_count",mismatchTotal);value.put("read_mismatch_record_limit",1);
        value.put("read_mismatch_records_truncated",mismatchTotal>1);
        value.put("retained_graph_stamps_released_at_terminal",ended&&capturedStamp==null&&afterStamp==null);
        value.put("node_text_recorded",false);value.put("screenshot_pixels_recorded",false);
        if(lastSavedGraphChange!=null)value.put("last_native_saved_graph_change",copyMap(lastSavedGraphChange));
        if(lastSeedDecision!=null){value.put("last_native_seed_decision",copyMap(lastSeedDecision));
            value.put("native_seed_admission_count",seedAdmissions);}
        value.put("grants_action_authority",false);value.put("changes_deadline",false);return value;
    }
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    private static Map<String,Object> copyMap(Map<?,?> source){
        Map<String,Object> out=map();for(Map.Entry<?,?> entry:source.entrySet())
            if(entry.getKey() instanceof String)out.put((String)entry.getKey(),copyValue(entry.getValue()));
        return out;
    }
    private static Object copyValue(Object value){
        if(value instanceof Map<?,?>)return copyMap((Map<?,?>)value);
        if(value instanceof List<?>){List<Object> out=new ArrayList<Object>();for(Object item:(List<?>)value)out.add(copyValue(item));return out;}
        return value;
    }
    private static void append(List<Map<String,Object>> rows,Map<String,Object> row,int limit){
        if(rows.size()==limit)rows.remove(0);rows.add(Collections.unmodifiableMap(row));
    }
    private static List<Map<String,Object>> copyRows(List<Map<String,Object>> rows){
        List<Map<String,Object>> copy=new ArrayList<Map<String,Object>>();for(Map<String,Object> row:rows)copy.add(new LinkedHashMap<String,Object>(row));return copy;
    }
    /** Already-observed selected-App values; content is reduced to fixed hashes. */
    static final class NodeStamp {
        final String id,path,signature,flags;
        final int left,top,right,bottom;
        NodeStamp(String id,String path,String signature,String flags,int left,int top,int right,int bottom){
            if(id==null||!id.matches("n[0-9]{1,4}")||path==null||path.length()>240||!path.matches("0(?:/[0-9]+)*")
                    ||!sha(signature)||!sha(flags))throw new IllegalArgumentException("bounded node stamp required");
            this.id=id;this.path=path;this.signature=signature;this.flags=flags;
            this.left=left;this.top=top;this.right=right;this.bottom=bottom;
        }
        Map<String,Object> evidence(){Map<String,Object> x=map();x.put("signature_sha256",signature);x.put("state_flags_sha256",flags);
            List<Integer> bounds=new ArrayList<Integer>();bounds.add(left);bounds.add(top);bounds.add(right);bounds.add(bottom);x.put("bounds",bounds);return x;}
        boolean same(NodeStamp other){return other!=null&&signature.equals(other.signature)&&flags.equals(other.flags)
                &&left==other.left&&top==other.top&&right==other.right&&bottom==other.bottom;}
    }
    static final class GraphStamp {
        final String packageName,generation,ownerSha,appTree,state,window;
        final int displayId,windowId;
        final boolean truncated;
        final Map<String,NodeStamp> nodes;
        final Map<String,String> idPaths;
        GraphStamp(String pkg,String generation,String owner,int display,int windowId,String appTree,String state,String window,
                   boolean truncated,List<NodeStamp> source){
            if(pkg==null||generation==null||!sha(owner)||display<0||!sha(appTree)||!sha(state)||!sha(window)
                    ||source==null||source.size()>MAX_NODES)throw new IllegalArgumentException("bounded graph stamp required");
            packageName=pkg;this.generation=generation;ownerSha=owner;displayId=display;this.windowId=windowId;
            this.appTree=appTree;this.state=state;this.window=window;this.truncated=truncated;
            TreeMap<String,NodeStamp> rows=new TreeMap<String,NodeStamp>();TreeMap<String,String> ids=new TreeMap<String,String>();
            for(NodeStamp n:source)if(n==null||rows.put(n.path,n)!=null||ids.put(n.id,n.path)!=null)throw new IllegalArgumentException("duplicate node stamp");
            nodes=Collections.unmodifiableMap(rows);idPaths=Collections.unmodifiableMap(ids);
        }
        Map<String,Object> identity(){Map<String,Object> x=map();x.put("app_tree_sha256",appTree);x.put("observation_state_sha256",state);
            x.put("window_metadata_sha256",window);x.put("retained_nodes",nodes.size());x.put("truncated",truncated);return x;}
    }
    static Map<String,Object> difference(GraphStamp before,GraphStamp after,String selectedId){
        if(before==null||after==null||!before.packageName.equals(after.packageName)||!before.generation.equals(after.generation)
                ||!before.ownerSha.equals(after.ownerSha)||before.displayId!=after.displayId||before.windowId!=after.windowId)return null;
        Map<String,Object> value=map();value.put("schema","hepta.native-graph-difference.v1");
        value.put("package",before.packageName);value.put("background_generation",before.generation);value.put("owner_sha256",before.ownerSha);
        value.put("display_id",before.displayId);value.put("window_id",before.windowId);value.put("before",before.identity());value.put("after",after.identity());
        value.put("app_tree_equal",before.appTree.equals(after.appTree));value.put("observation_state_equal",before.state.equals(after.state));
        value.put("window_metadata_equal",before.window.equals(after.window));
        String selected=selectedId==null?null:before.idPaths.get(selectedId);value.put("selected_original_path",selected);
        NodeStamp oldTarget=selected==null?null:before.nodes.get(selected),newTarget=selected==null?null:after.nodes.get(selected);
        value.put("selected_path_present_after",selected==null?null:newTarget!=null);
        value.put("selected_stamp_equal",oldTarget==null?null:oldTarget.same(newTarget));
        TreeSet<String> paths=new TreeSet<String>(before.nodes.keySet());paths.addAll(after.nodes.keySet());
        List<Map<String,Object>> changes=new ArrayList<Map<String,Object>>();int changed=0;
        for(String path:paths){NodeStamp a=before.nodes.get(path),b=after.nodes.get(path);if(a!=null&&a.same(b))continue;changed++;
            if(changes.size()<MAX_NODE_DIFFS){Map<String,Object> row=map();row.put("native_path",path);
                row.put("before",a==null?null:a.evidence());row.put("after",b==null?null:b.evidence());changes.add(row);}}
        value.put("changed_retained_path_count",changed);value.put("node_differences",changes);value.put("node_difference_limit",MAX_NODE_DIFFS);
        value.put("node_differences_truncated",changed>MAX_NODE_DIFFS);value.put("complete_tree_claimed",false);
        value.put("node_text_recorded",false);value.put("fully_unoccluded_claimed",false);value.put("grants_action_authority",false);return value;
    }
}
