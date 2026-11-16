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
    enum Phase { OBSERVE, DOM_SCOPE_BRACKET, SHOPPING_DOM_ELIGIBILITY,
        MAIN_QUEUE, MAIN_READ, MAIN_WAIT, NATIVE_QUEUE, NATIVE_READ, NATIVE_WAIT,
        NATIVE_DOM_BRACKET, NATIVE_READ_GRAPH, NATIVE_FINAL_RECHECK }
    static final int MAX_SPANS=96;
    static final class Span {
        final WebObservationTiming owner;final Phase phase;final long started,deadline;final int ordinal;
        long ended=-1;String outcome="pending",errorType;Boolean predicateResult;
        Span(WebObservationTiming owner,Phase phase,long started,long deadline,int ordinal){
            this.owner=owner;this.phase=phase;this.started=started;this.deadline=deadline;this.ordinal=ordinal;
        }
    }
    private final String taskId,traceId=UUID.randomUUID().toString().replace("-","");
    private final Clock clock;private final long started,deadline;
    private final List<Span> spans=new ArrayList<Span>();private int dropped;
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
    private static void finish(Span span,Throwable failure,Boolean predicateResult){
        if(span==null)return;
        synchronized(span.owner){
            if(span.ended>=0)return;
            span.ended=span.owner.clock.now();span.predicateResult=predicateResult;
            span.outcome=failure==null?"completed":span.ended>=span.deadline?"deadline_expired":"failed";
            span.errorType=failure==null?null:failure.getClass().getName();
        }
    }
    JSONObject snapshot()throws Exception{
        final Object[][] rows;final int omitted;final long captured;
        synchronized(this){
            captured=clock.now();omitted=dropped;rows=new Object[spans.size()][];
            for(int i=0;i<spans.size();i++){
                Span s=spans.get(i);rows[i]=new Object[]{s.ordinal,s.phase.name().toLowerCase(java.util.Locale.ROOT),
                        s.started,s.deadline,s.ended,s.outcome,s.errorType,s.predicateResult};
            }
        }
        JSONArray events=new JSONArray();
        for(Object[] row:rows){
            long start=((Long)row[2]).longValue(),limit=((Long)row[3]).longValue(),end=((Long)row[4]).longValue();
            events.put(new JSONObject().put("ordinal",row[0]).put("phase",row[1])
                    .put("started_elapsed_ms",start).put("deadline_elapsed_ms",limit)
                    .put("finished_elapsed_ms",end<0?JSONObject.NULL:Long.valueOf(end))
                    .put("duration_ms",end<0?JSONObject.NULL:Long.valueOf(end-start))
                    .put("outcome",row[5]).put("error_type",row[6]==null?JSONObject.NULL:row[6])
                    .put("predicate_result",row[7]==null?JSONObject.NULL:row[7])
                    .put("deadline_exceeded_at_snapshot",captured>=limit)
                    .put("deadline_exceeded_at_finish",end<0?JSONObject.NULL:Boolean.valueOf(end>=limit)));
        }
        return new JSONObject().put("schema","hepta.web-observation-timing.v1").put("task_id",taskId)
                .put("trace_id",traceId).put("started_elapsed_ms",started).put("deadline_elapsed_ms",deadline)
                .put("snapshot_elapsed_ms",captured).put("maximum_spans",MAX_SPANS).put("dropped_spans",omitted)
                .put("spans",events).put("diagnostics_only",true).put("grants_action_capability",false)
                .put("contains_page_text",false).put("pending_spans_do_not_prove_native_drain",true);
    }
}
