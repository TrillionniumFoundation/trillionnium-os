package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/** Bounded, task-local diagnostics only. Never grants authority or changes a read deadline.
 * Main/native threads append fixed labels and clocks in memory; the controller persists a snapshot.
 * A pending span means the call had not ended at snapshot time, not that native IO was drained. */
final class WebObservationTiming {
    interface Clock { long now(); }
    interface FailureDiagnostic { String[] collect()throws Exception; }
    interface PrivateEvidenceWriter { void write(String name,byte[] bytes)throws Exception; }
    private static final int MAX_PRIVATE_NATIVE_PAIR_BYTES=2*1024*1024;
    private static final String CONTAINMENT_FAILURE="visible native recommendation escaped its container";
    enum Phase { OBSERVE, DOM_SCOPE_BRACKET, SHOPPING_DOM_ELIGIBILITY,
        MAIN_QUEUE, MAIN_READ, MAIN_WAIT, NATIVE_QUEUE, NATIVE_READ, NATIVE_WAIT,
        NATIVE_DOM_BRACKET, NATIVE_READ_GRAPH, NATIVE_FINAL_RECHECK }
    static final int MAX_SPANS=96;
    static final class Span {
        final WebObservationTiming owner;final Phase phase;final long started,deadline;final int ordinal;
        long ended=-1;String outcome="pending",errorType,nativeChangeDiagnostic,nativeChangeStructure;Boolean predicateResult;
        private Throwable geometryFailure;private String nativeContainmentDiagnostic,nativeContainmentPair;
        Span(WebObservationTiming owner,Phase phase,long started,long deadline,int ordinal){
            this.owner=owner;this.phase=phase;this.started=started;this.deadline=deadline;this.ordinal=ordinal;
        }
    }
    private final String taskId,traceId=UUID.randomUUID().toString().replace("-","");
    private final Clock clock;private final long started,deadline;
    private final List<Span> spans=new ArrayList<Span>();private int dropped;
    private Span containmentSpan;private FailureDiagnostic pendingNativeDiagnostic;
    WebObservationTiming(String taskId,long deadline,Clock clock){
        this.taskId=taskId;this.deadline=deadline;this.clock=clock;started=clock.now();
    }
    String id(){return traceId;}
    static Span begin(WebObservationTiming timing,Phase phase,long deadline){
        if(timing==null||phase==null)return null;
        synchronized(timing){
            if(timing.spans.size()>=MAX_SPANS){timing.dropped++;return null;}
            Span span=new Span(timing,phase,timing.clock.now(),deadline,timing.spans.size());
            timing.spans.add(span);return span;
        }
    }
    static void complete(Span span){finish(span,null,null);}
    static void complete(Span span,boolean predicateResult){finish(span,null,Boolean.valueOf(predicateResult));}
    static void failed(Span span,Throwable failure){finish(span,failure,null);}
    /** Failure-only metadata; the original end time and exception remain authoritative. */
    static void failureStructure(Span span,Throwable failure,JSONArray before,JSONArray after,String targetPath){
        try{
            if(span==null||span.phase!=Phase.NATIVE_DOM_BRACKET||!(failure instanceof WebNativeObservationChanged))return;
            WebNativeObservationChanged changed=(WebNativeObservationChanged)failure;
            synchronized(span.owner){
                if(span.ended<0||span.errorType==null||!span.errorType.equals(failure.getClass().getName())
                        ||!java.util.Objects.equals(span.nativeChangeDiagnostic,changed.diagnostic)
                        ||span.nativeChangeStructure!=null)return;
            }
            String structure=WebNativeObservationChanged.structureAfterFailure(changed,before,after,targetPath);
            synchronized(span.owner){
                if(span.nativeChangeStructure==null)span.nativeChangeStructure=structure;
            }
        }catch(Throwable unavailable){/* Diagnostic failure must not replace the original rejection. */}
    }
    /** Register only the ended span's same failure. Heavy diagnostics are deferred until observation finally. */
    static void failureGeometry(Span span,Throwable failure,FailureDiagnostic provider){
        try{
            if(span==null||span.phase!=Phase.NATIVE_DOM_BRACKET||failure==null||failure.getClass()!=IllegalArgumentException.class
                    ||!CONTAINMENT_FAILURE.equals(failure.getMessage())||provider==null)return;
            synchronized(span.owner){
                if(span.ended<0||span.geometryFailure!=failure||span.owner.containmentSpan!=null)return;
                span.owner.containmentSpan=span;span.owner.pendingNativeDiagnostic=provider;
            }
        }catch(Throwable unavailable){/* Never replace the original rejection or end time. */}
    }
    /** No wait for an unfinished worker. Only evidence already registered at finalization can be persisted. */
    void persistPrivateNativePair(Throwable observationFailure,PrivateEvidenceWriter writer){
        Span span;FailureDiagnostic provider;
        synchronized(this){
            span=containmentSpan;provider=pendingNativeDiagnostic;pendingNativeDiagnostic=null;
            if(span==null||provider==null)return;
        }
        try{
            if(observationFailure==null||writer==null)throw new IllegalArgumentException("failed observation required");
            String[] value=provider.collect();
            if(value==null){
                synchronized(this){span.nativeContainmentPair=pairState(false,"unavailable",null,null,0);}
                return;
            }
            if(value.length!=2||value[0]==null)throw new IllegalArgumentException("diagnostic shape");
            String metadata=boundedContainmentMetadata(value[0]);
            synchronized(this){span.nativeContainmentDiagnostic=metadata;}
            if(value[1]==null){
                synchronized(this){span.nativeContainmentPair=pairState(false,"unavailable",null,null,0);}
                return;
            }
            if(!Boolean.TRUE.equals(new JSONObject(metadata).get("available"))||value[1].length()>MAX_PRIVATE_NATIVE_PAIR_BYTES)
                throw new IllegalArgumentException("private pair availability or length");
            byte[] bytes=value[1].getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if(bytes.length>MAX_PRIVATE_NATIVE_PAIR_BYTES)throw new IllegalArgumentException("private pair byte budget");
            String name="web-native-geometry-pair-"+traceId+".json";
            byte[] digest=java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder hash=new StringBuilder(64);
            for(byte b:digest)hash.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
            writer.write(name,bytes);
            synchronized(this){
                span.nativeContainmentPair=new JSONObject(pairState(true,"persisted",name,hash.toString(),bytes.length))
                        .put("native_failure_matches_observation_failure",span.geometryFailure==observationFailure).toString();
            }
        }catch(Throwable unavailable){
            try{synchronized(this){span.nativeContainmentPair=pairState(false,"private_write_failed",null,null,0);}}
            catch(Throwable ignored){}
        }
    }
    private static String pairState(boolean available,String reason,String name,String sha,int bytes)throws Exception{
        return new JSONObject().put("schema","hepta.private-native-pair-reference.v1").put("available",available)
                .put("reason",reason).put("filename",name==null?JSONObject.NULL:name).put("sha256",sha==null?JSONObject.NULL:sha)
                .put("bytes",bytes).put("complete",available).put("maximum_bytes",MAX_PRIVATE_NATIVE_PAIR_BYTES)
                .put("private_payload_contains_page_text",true).put("grants_action_capability",false).toString();
    }
    /** Whitelist every public field. Unknown names, arbitrary labels and row values cannot enter timing JSON. */
    private static String boundedContainmentMetadata(String raw)throws Exception{
        if(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>16384)throw new IllegalArgumentException("diagnostic metadata budget");
        JSONObject v=new JSONObject(raw),out=new JSONObject().put("schema","hepta.native-containment-failure.v1")
                .put("contains_page_text",false).put("grants_action_capability",false);
        if(!"hepta.native-containment-failure.v1".equals(v.get("schema"))||!Boolean.FALSE.equals(v.get("contains_page_text"))
                ||!Boolean.FALSE.equals(v.get("grants_action_capability")))throw new IllegalArgumentException("diagnostic metadata schema");
        if(Boolean.FALSE.equals(v.get("available"))){
            Object reason=v.get("reason");
            if(!"private_pair_exceeds_cap".equals(reason)&&!"diagnostic_unavailable".equals(reason))
                throw new IllegalArgumentException("diagnostic unavailable reason");
            return out.put("available",false).put("reason",reason).toString();
        }
        if(!Boolean.TRUE.equals(v.get("available")))throw new IllegalArgumentException("diagnostic available flag");
        out.put("available",true);
        for(String key:new String[]{"native_path","recommendation_native_path","target_native_path"}){
            Object value=v.get(key);
            if(!(value instanceof String)||!((String)value).matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}"))
                throw new IllegalArgumentException("diagnostic path");
            out.put(key,value);
        }
        Object side=v.get("side");if(!"before".equals(side)&&!"after".equals(side))throw new IllegalArgumentException("diagnostic side");
        out.put("side",side);
        for(String key:new String[]{"row_bounds","container_bounds","target_bounds"}){
            JSONArray a=v.getJSONArray(key);if(a.length()!=4)throw new IllegalArgumentException("diagnostic bounds");
            JSONArray copy=new JSONArray();
            for(int i=0;i<4;i++){
                Object value=a.get(i);if(!(value instanceof Integer)&&!(value instanceof Long))throw new IllegalArgumentException("diagnostic integer bounds");
                long n=((Number)value).longValue();if(n<Integer.MIN_VALUE||n>Integer.MAX_VALUE)throw new IllegalArgumentException("diagnostic bounds range");
                copy.put(n);
            }
            out.put(key,copy);
        }
        for(String key:new String[]{"visible","container_contains_row","row_overlaps_target","original_overlap_evaluated","complete_source_snapshots"}){
            Object value=v.get(key);if(!(value instanceof Boolean))throw new IllegalArgumentException("diagnostic boolean");
            out.put(key,value);
        }
        if(!Boolean.TRUE.equals(v.get("visible"))||!Boolean.TRUE.equals(v.get("complete_source_snapshots")))
            throw new IllegalArgumentException("diagnostic snapshot flags");
        for(String key:new String[]{"before_raw_sha256","after_raw_sha256"}){
            Object value=v.get(key);if(!(value instanceof String)||!((String)value).matches("[0-9a-f]{64}"))throw new IllegalArgumentException("diagnostic hash");
            out.put(key,value);
        }
        for(String key:new String[]{"before_row_count","after_row_count"}){
            Object value=v.get(key);if(!(value instanceof Integer)&&!(value instanceof Long))throw new IllegalArgumentException("diagnostic count");
            long n=((Number)value).longValue();if(n<1||n>1024)throw new IllegalArgumentException("diagnostic count budget");
            out.put(key,n);
        }
        return out.toString();
    }
    private static void finish(Span span,Throwable failure,Boolean predicateResult){
        if(span==null)return;
        synchronized(span.owner){
            if(span.ended>=0)return;
            span.ended=span.owner.clock.now();span.predicateResult=predicateResult;
            span.outcome=failure==null?"completed":span.ended>=span.deadline?"deadline_expired":"failed";
            span.errorType=failure==null?null:failure.getClass().getName();
            if(span.phase==Phase.NATIVE_DOM_BRACKET&&failure!=null&&failure.getClass()==IllegalArgumentException.class
                    &&CONTAINMENT_FAILURE.equals(failure.getMessage()))span.geometryFailure=failure;
            if(span.phase==Phase.NATIVE_DOM_BRACKET&&failure instanceof WebNativeObservationChanged)
                span.nativeChangeDiagnostic=((WebNativeObservationChanged)failure).diagnostic;
        }
    }
    JSONObject snapshot()throws Exception{
        final Object[][] rows;final int omitted;final long captured;
        synchronized(this){
            captured=clock.now();omitted=dropped;rows=new Object[spans.size()][];
            for(int i=0;i<spans.size();i++){
                Span s=spans.get(i);rows[i]=new Object[]{s.ordinal,s.phase.name().toLowerCase(java.util.Locale.ROOT),
                        s.started,s.deadline,s.ended,s.outcome,s.errorType,s.predicateResult,s.nativeChangeDiagnostic,s.nativeChangeStructure,
                        s.nativeContainmentDiagnostic,s.nativeContainmentPair};
            }
        }
        JSONArray events=new JSONArray();
        for(Object[] row:rows){
            long start=((Long)row[2]).longValue(),limit=((Long)row[3]).longValue(),end=((Long)row[4]).longValue();
            JSONObject event=new JSONObject().put("ordinal",row[0]).put("phase",row[1])
                    .put("started_elapsed_ms",start).put("deadline_elapsed_ms",limit)
                    .put("finished_elapsed_ms",end<0?JSONObject.NULL:Long.valueOf(end))
                    .put("duration_ms",end<0?JSONObject.NULL:Long.valueOf(end-start))
                    .put("outcome",row[5]).put("error_type",row[6]==null?JSONObject.NULL:row[6])
                    .put("predicate_result",row[7]==null?JSONObject.NULL:row[7])
                    .put("deadline_exceeded_at_snapshot",captured>=limit)
                    .put("deadline_exceeded_at_finish",end<0?JSONObject.NULL:Boolean.valueOf(end>=limit));
            if(row[8]!=null){
                try{event.put("native_change_diagnostic",new JSONObject((String)row[8]));}
                catch(Exception ignored){event.put("native_change_diagnostic",new JSONObject().put("available",false));}
            }
            if(row[9]!=null){
                try{event.put("native_change_structure",new JSONObject((String)row[9]));}
                catch(Exception ignored){event.put("native_change_structure",new JSONObject().put("available",false));}
            }
            for(int i=10;i<=11;i++)if(row[i]!=null){
                String key=i==10?"native_containment_diagnostic":"native_containment_private_pair";
                try{event.put(key,new JSONObject((String)row[i]));}
                catch(Exception ignored){event.put(key,new JSONObject().put("available",false));}
            }
            events.put(event);
        }
        return new JSONObject().put("schema","hepta.web-observation-timing.v1").put("task_id",taskId)
                .put("trace_id",traceId).put("started_elapsed_ms",started).put("deadline_elapsed_ms",deadline)
                .put("snapshot_elapsed_ms",captured).put("maximum_spans",MAX_SPANS).put("dropped_spans",omitted)
                .put("spans",events).put("diagnostics_only",true).put("grants_action_capability",false)
                .put("contains_page_text",false).put("pending_spans_do_not_prove_native_drain",true);
    }
}
