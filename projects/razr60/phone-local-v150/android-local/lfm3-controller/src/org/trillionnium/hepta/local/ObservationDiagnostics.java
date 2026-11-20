package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Bounded non-authoritative values only: no Android object, I/O, sampling or effect. */
final class ObservationDiagnostics {
    static final int MAX_RECORDS=96,MAX_TRANSITIONS=16,MAX_FRAMES=6,MAX_NODE_DIFFS=8,MAX_NODES=512,MAX_JSON_BYTES=16384;
    // Same existing full native-census limits; these do not expand observation collection.
    static final int MAX_CENSUS_NODES=1536,MAX_CENSUS_TEXT=32768;
    static final int MAX_COMPACT_NODE_DIFFS=64;
    enum Event {
        SAMPLE_START,SAMPLE_NO_ROOT,SAMPLE_STALE_ROOT,SAMPLE_ERROR,SAMPLE_EVENT_RESET,SAMPLE_EVENT_RECHECKED,
        SAMPLE_KEY_CHANGED,SAMPLE_MISSING,SAMPLE_READY,SAMPLE_WAIT,SAMPLE_EXPIRED,SAMPLE_CANCELLED,
        SCREENSHOT_INTERVAL_WAIT,CAPTURE_START,CAPTURE_CALLBACK_OK,CAPTURE_CALLBACK_FAIL,
        SCREENSHOT_GRAPH_MISSING,SCREENSHOT_GRAPH_STALE,SCREENSHOT_GRAPH_CHANGED,
        SAVED_GRAPH_MISSING,SAVED_GRAPH_STALE,SAVED_GRAPH_CHANGED,CAPTURE_EVENT_RESET,CAPTURE_EVENT_RECHECKED,
        CAPTURE_RETRY,INTERVAL_RETRY,POST_EFFECT_WINDOW_RECHECK_STARTED,POST_EFFECT_WINDOW_RECHECK_PASSED,
        POST_EFFECT_WINDOW_RECHECK_REJECTED,PUBLISHED,EVENT_TARGET,EVENT_UNKNOWN,REQUEST_ERROR,WORKER_ABANDONED
    }
    private static final String[] PHASES={"queued","sample_graph","sample_gap","screenshot_callback",
        "screenshot_copy","screenshot_graph","png_encode","png_fsync","png_hash","saved_graph","publish","retry_gap","publication_window_recheck"};
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
    private Map<String,Object> lastSavedGraphChange,lastSeedDecision,lastSampleGraphChange;private long seedAdmissions;
    private GraphStamp previousSampleStamp;
    private Map<String,Object> lastFullGraphChange;private long fullGraphChanges;

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
    synchronized void note(Event event){if(!ended&&event!=null)counts[event.ordinal()]=plus(counts[event.ordinal()],1);}
    synchronized void worker(boolean active){if(!ended)workerActive=active;}
    synchronized void reset(){if(!ended){previousSampleKey=null;previousSampleStamp=null;}}
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
    /** Copied retained-node hashes only; this does not claim a full census. */
    synchronized void sampleGraphChange(GraphStamp after,long now){
        if(ended)return;
        Map<String,Object> delta=difference(previousSampleStamp,after,null);
        if(delta!=null&&(!Boolean.TRUE.equals(delta.get("app_tree_equal"))
                ||!Boolean.TRUE.equals(delta.get("observation_state_equal"))
                ||!Boolean.TRUE.equals(delta.get("window_metadata_equal")))){
            delta.put("stage","sample_graph");delta.put("elapsed_ms",clock(now)-started);
            delta.put("sampling_or_action_changed",false);
            lastSampleGraphChange=Collections.unmodifiableMap(delta);
        }
        previousSampleStamp=after;
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
    /** Existing immutable census values only. This never admits an observation or action. */
    synchronized void fullGraphChange(String stage,CensusStamp before,CensusStamp after,long now){
        if(ended||!("screenshot_graph".equals(stage)||"saved_graph".equals(stage)))return;
        Map<String,Object> delta=map();delta.put("schema","hepta.native-observation-census-difference.v1");
        delta.put("stage",stage);delta.put("elapsed_ms",clock(now)-started);
        delta.put("full_census_compared",false);delta.put("node_difference_limit",MAX_NODE_DIFFS);
        delta.put("node_text_recorded",false);delta.put("screenshot_pixels_recorded",false);
        delta.put("grants_action_authority",false);delta.put("grants_publication",false);
        delta.put("business_verified",false);delta.put("changes_deadline",false);
        delta.put("before",before==null?null:before.summary());delta.put("after",after==null?null:after.summary());
        if(before==null||after==null)delta.put("status","full_census_unavailable");
        else if(!before.belongs(this)||!after.belongs(this)||!before.identity.equals(after.identity)){
            delta.put("status","identity_mismatch");List<String> changed=new ArrayList<String>();
            TreeSet<String> keys=new TreeSet<String>(before.identity.keySet());keys.addAll(after.identity.keySet());
            for(String key:keys)if(!Objects.equals(before.identity.get(key),after.identity.get(key)))changed.add(key);
            delta.put("changed_identity_fields",Collections.unmodifiableList(changed));
            delta.put("both_match_request",before.belongs(this)&&after.belongs(this));
        }else{
            TreeSet<String> paths=new TreeSet<String>(before.nodes.keySet());paths.addAll(after.nodes.keySet());
            List<Map<String,Object>> details=new ArrayList<Map<String,Object>>(),compact=new ArrayList<Map<String,Object>>();int changed=0;
            for(String path:paths){Map<String,Object> a=before.nodes.get(path),b=after.nodes.get(path);
                if(a!=null&&a.equals(b))continue;changed++;
                List<String> fields=new ArrayList<String>();
                if(details.size()<MAX_NODE_DIFFS||compact.size()<MAX_COMPACT_NODE_DIFFS)
                    for(String key:CENSUS_NODE_KEYS)if(a==null||b==null||!Objects.equals(a.get(key),b.get(key)))fields.add(key);
                if(compact.size()<MAX_COMPACT_NODE_DIFFS)compact.add(compactCensusDifference(path,a,b,fields));
                if(details.size()<MAX_NODE_DIFFS){Map<String,Object> row=map();row.put("native_path",path);
                    row.put("parent_path",parentPath(path));row.put("changed_fields",Collections.unmodifiableList(fields));
                    row.put("before",a==null?null:censusNodeEvidence(a));row.put("after",b==null?null:censusNodeEvidence(b));
                    details.add(Collections.unmodifiableMap(row));
                }
            }
            delta.put("status","compared");delta.put("full_census_compared",true);
            delta.put("app_tree_equal",before.appTree.equals(after.appTree));delta.put("observation_state_equal",before.state.equals(after.state));
            delta.put("window_metadata_equal",before.window.equals(after.window));
            delta.put("changed_path_count",changed);delta.put("node_differences",Collections.unmodifiableList(details));
            delta.put("retained_detail_count",details.size());delta.put("node_differences_truncated",changed>details.size());
            delta.put("details_omitted_for_budget",false);
            delta.put("compact_difference_limit",MAX_COMPACT_NODE_DIFFS);
            delta.put("compact_node_differences",Collections.unmodifiableList(compact));
            delta.put("compact_retained_count",compact.size());delta.put("compact_omitted_count",changed-compact.size());
            delta.put("compact_truncated",changed>compact.size());delta.put("compact_omitted_for_budget",false);
        }
        lastFullGraphChange=Collections.unmodifiableMap(delta);fullGraphChanges=plus(fullGraphChanges,1);
    }
    synchronized void missingSample(){if(!ended){note(Event.SAMPLE_MISSING);previousSampleKey=null;previousSampleStamp=null;}}
    synchronized void published(String id,long now){if(!ended&&id(id)){publishedObservationId=id;note(Event.PUBLISHED);finish("published",now);}}
    synchronized void finish(String status,long now){
        if(ended)return;if(!"published".equals(status)&&!"failed".equals(status))return;
        now=clock(now);closePhase(now);terminal=status;ended=true;previousSampleStamp=null;
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
        value.put("node_text_recorded",false);value.put("screenshot_pixels_recorded",false);
        if(lastSampleGraphChange!=null)value.put("last_native_sample_graph_change",new LinkedHashMap<String,Object>(lastSampleGraphChange));
        if(lastSavedGraphChange!=null)value.put("last_native_saved_graph_change",new LinkedHashMap<String,Object>(lastSavedGraphChange));
        if(lastFullGraphChange!=null){value.put("last_native_full_graph_change",new LinkedHashMap<String,Object>(lastFullGraphChange));
            value.put("native_full_graph_change_count",fullGraphChanges);}
        if(lastSeedDecision!=null){value.put("last_native_seed_decision",new LinkedHashMap<String,Object>(lastSeedDecision));
            value.put("native_seed_admission_count",seedAdmissions);}
        value.put("grants_action_authority",false);value.put("changes_deadline",false);return value;
    }
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    private static void append(List<Map<String,Object>> rows,Map<String,Object> row,int limit){
        if(rows.size()==limit)rows.remove(0);rows.add(Collections.unmodifiableMap(row));
    }
    private static List<Map<String,Object>> copyRows(List<Map<String,Object>> rows){
        List<Map<String,Object>> copy=new ArrayList<Map<String,Object>>();for(Map<String,Object> row:rows)copy.add(new LinkedHashMap<String,Object>(row));return copy;
    }
    private static Set<String> keys(String csv){return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(csv.split(","))));}
    private static final Set<String> CENSUS_NODE_KEYS=keys("path,parent_class,package,window_id,class,view_id,text,description,label,ref_signature_sha256,bounds,visible,enabled,clickable,editable,scrollable,focused,password,selected,checkable,checked,children,scroll_actions,ime_enter,input_sha256,action_click");
    private static final Set<String> CENSUS_FLAGS=keys("visible,enabled,clickable,editable,scrollable,focused,password,selected,checkable,checked,action_click");
    private static final Set<String> CENSUS_IDENTITY=keys("task_id,owner_sha256,package,background_generation,display_id,window_id,rotation,width,height,root_bounds,authorization_sha256,selection_sha256,target_sha256,goal_sha256");
    private static final Set<String> CENSUS_PROFILE=keys("profile_target_sha256,profile_user_id,profile_user_serial,profile_full_uid,profile_task_id,profile_parent_task_id,profile_task_token_id");
    private static String parentPath(String path){int end=path.lastIndexOf('/');return end<0?null:path.substring(0,end);}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("bounded copied native census required");}
    private static String string(Map<String,Object> value,String key,int limit){Object raw=value.get(key);require(raw instanceof String&&((String)raw).length()<=limit);return (String)raw;}
    private static long integer(Map<String,Object> value,String key){Object raw=value.get(key);require(raw instanceof Integer||raw instanceof Long);return ((Number)raw).longValue();}
    private static List<Integer> bounds(Object raw){require(raw instanceof List&&((List<?>)raw).size()==4);List<Integer> result=new ArrayList<Integer>();
        for(Object part:(List<?>)raw){require(part instanceof Integer||part instanceof Long);long n=((Number)part).longValue();require(n>=Integer.MIN_VALUE&&n<=Integer.MAX_VALUE);result.add((int)n);}return Collections.unmodifiableList(result);}
    /** Pure diagnostic carrier. Values originate from a completed full BFS, not retained rows. */
    static final class CensusStamp {
        final Map<String,Object> identity;final Map<String,Map<String,Object>> nodes;
        final String appTree,state,window;
        CensusStamp(Map<String,Object> identity,String appTree,String state,String window,int visited,List<Map<String,Object>> source){
            require(identity!=null&&source!=null&&!source.isEmpty()&&source.size()<=MAX_CENSUS_NODES&&visited==source.size()
                    &&sha(appTree)&&sha(state)&&sha(window));
            TreeSet<String> allowed=new TreeSet<String>(CENSUS_IDENTITY);
            if(identity.containsKey("profile_target_sha256"))allowed.addAll(CENSUS_PROFILE);
            require(identity.keySet().equals(allowed));Map<String,Object> ids=new TreeMap<String,Object>(identity);
            require(id(string(ids,"task_id",32))&&sha(string(ids,"owner_sha256",64)));
            require(string(ids,"package",192).matches("[A-Za-z0-9_.]+")&&string(ids,"background_generation",36).matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"));
            for(String key:Arrays.asList("authorization_sha256","selection_sha256","target_sha256","goal_sha256"))require(sha(string(ids,key,64)));
            require(integer(ids,"display_id")>1&&integer(ids,"window_id")>=0&&integer(ids,"rotation")>=0&&integer(ids,"rotation")<=3
                    &&integer(ids,"width")>0&&integer(ids,"height")>0);ids.put("root_bounds",bounds(ids.get("root_bounds")));
            if(ids.containsKey("profile_target_sha256")){
                require(sha(string(ids,"profile_target_sha256",64))&&integer(ids,"profile_user_id")>0&&integer(ids,"profile_user_serial")>0
                        &&integer(ids,"profile_full_uid")/100000==integer(ids,"profile_user_id")
                        &&integer(ids,"profile_task_id")>0&&integer(ids,"profile_parent_task_id")>0
                        &&integer(ids,"profile_task_id")!=integer(ids,"profile_parent_task_id")
                        &&string(ids,"profile_task_token_id",36).matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"));
            }
            this.identity=Collections.unmodifiableMap(ids);this.appTree=appTree;this.state=state;this.window=window;
            TreeMap<String,Map<String,Object>> rows=new TreeMap<String,Map<String,Object>>();int text=0;
            for(Map<String,Object> value:source){require(value!=null&&value.keySet().equals(CENSUS_NODE_KEYS));Map<String,Object> row=new TreeMap<String,Object>(value);
                String path=string(row,"path",240);require(path.matches("0(?:/[0-9]+)*")&&!rows.containsKey(path));
                require(string(row,"package",192).equals(ids.get("package"))&&integer(row,"window_id")==integer(ids,"window_id"));
                require(!string(row,"class",128).isEmpty());string(row,"parent_class",128);string(row,"view_id",256);
                text+=string(row,"text",1024).length()+string(row,"description",1024).length();require(text<=MAX_CENSUS_TEXT);
                if(row.get("label")!=null)string(row,"label",4096);
                string(row,"scroll_actions",1024);string(row,"ime_enter",512);
                for(String key:CENSUS_FLAGS)require(row.get(key) instanceof Boolean);
                for(String key:Arrays.asList("ref_signature_sha256","input_sha256"))require(row.get(key)==null||sha(string(row,key,64)));
                require(integer(row,"children")>=0&&integer(row,"children")<=MAX_CENSUS_NODES);row.put("bounds",bounds(row.get("bounds")));
                rows.put(path,Collections.unmodifiableMap(row));
            }
            require(rows.containsKey("0")&&rows.get("0").get("bounds").equals(ids.get("root_bounds")));
            for(Map.Entry<String,Map<String,Object>> entry:rows.entrySet()){
                String path=entry.getKey();Map<String,Object> row=entry.getValue();String parent=parentPath(path);
                if(parent!=null){Map<String,Object> p=rows.get(parent);require(p!=null&&row.get("parent_class").equals(p.get("class")));
                    long index=Long.parseLong(path.substring(path.lastIndexOf('/')+1));require(index>=0&&index<integer(p,"children"));}
                for(long i=0;i<integer(row,"children");i++)require(rows.containsKey(path+"/"+i));
            }
            nodes=Collections.unmodifiableMap(rows);
        }
        boolean belongs(ObservationDiagnostics d){return d.taskId.equals(identity.get("task_id"))&&d.ownerSha.equals(identity.get("owner_sha256"))
                &&d.packageName.equals(identity.get("package"))&&d.generation.equals(identity.get("background_generation"))&&d.displayId==integer(identity,"display_id");}
        Map<String,Object> summary(){Map<String,Object> out=map();out.put("app_tree_sha256",appTree);out.put("observation_state_sha256",state);
            out.put("window_metadata_sha256",window);out.put("full_native_nodes",nodes.size());return Collections.unmodifiableMap(out);}
    }
    /** Field names, changed geometry and content hashes only. This is a bounded
     * diagnostic projection of copied full censuses, never a comparison policy. */
    private static Map<String,Object> compactCensusDifference(String path,Map<String,Object> before,
            Map<String,Object> after,List<String> fields){
        Map<String,Object> out=map();out.put("native_path",path);
        out.put("change_type",before==null?"added":after==null?"removed":"changed");
        out.put("changed_fields",Collections.unmodifiableList(fields));
        if(fields.contains("bounds")){out.put("before_bounds",before==null?null:before.get("bounds"));
            out.put("after_bounds",after==null?null:after.get("bounds"));}
        Map<String,Object> textHashes=map();
        for(String key:Arrays.asList("text","description","label"))if(fields.contains(key)){
            String a=before==null?null:(String)before.get(key),b=after==null?null:(String)after.get(key);
            Map<String,Object> hashes=map();hashes.put("before",a==null?null:contentHash(a));hashes.put("after",b==null?null:contentHash(b));
            textHashes.put(key,Collections.unmodifiableMap(hashes));
        }
        if(!textHashes.isEmpty())out.put("changed_text_sha256",Collections.unmodifiableMap(textHashes));
        return Collections.unmodifiableMap(out);
    }
    private static Map<String,Object> censusNodeEvidence(Map<String,Object> node){
        Map<String,Object> out=map();for(String key:Arrays.asList("package","window_id","class","parent_class","view_id","bounds","children"))out.put(key,node.get(key));
        Map<String,Object> flags=map();for(String key:CENSUS_FLAGS)flags.put(key,node.get(key));out.put("flags",Collections.unmodifiableMap(flags));
        for(String key:Arrays.asList("text","description","label","scroll_actions","ime_enter")){
            String value=(String)node.get(key);Map<String,Object> content=map();content.put("utf16_length",value==null?null:value.length());
            content.put("sha256",value==null?null:contentHash(value));out.put(key,Collections.unmodifiableMap(content));}
        out.put("ref_signature_sha256",node.get("ref_signature_sha256"));out.put("input_sha256",node.get("input_sha256"));return Collections.unmodifiableMap(out);
    }
    private static String contentHash(String value){
        try{byte[] digest=java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            char[] hex="0123456789abcdef".toCharArray(),result=new char[digest.length*2];for(int i=0;i<digest.length;i++){int b=digest[i]&255;result[i*2]=hex[b>>>4];result[i*2+1]=hex[b&15];}return new String(result);}
        catch(java.security.NoSuchAlgorithmException unavailable){throw new IllegalStateException("SHA-256 unavailable",unavailable);}
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
