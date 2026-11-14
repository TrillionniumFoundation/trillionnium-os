package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A bounded action lifetime. Retirement is not physical worker completion. */
public final class ActionExecutionState {
    public interface Clock { long elapsedRealtime(); }
    public static final int MAX_PHASES=64;
    public final String operationId,taskId,modelRunId,observationId,authorizationSha256,backgroundGeneration;
    public final int windowId,displayId;
    public final long queuedElapsed,deadlineElapsed;
    private final Clock clock;
    private final List<Map<String,Object>> phases=new ArrayList<Map<String,Object>>();
    private boolean retired,drained,effectEntered,effectReturned,phasesTruncated,published,publicationAllowed;
    private Boolean apiAccepted;
    private String retirementReason;
    private long drainedElapsed=-1,lastClockElapsed;

    public ActionExecutionState(String operation,String task,String run,String observation,String authorization,
            int window,int display,String generation,long queued,long deadline,Clock clock){
        require(id(operation)&&id(task)&&id(run)&&id(observation),"action identity required");
        require(authorization!=null&&authorization.matches("[0-9a-f]{64}"),"action authorization hash required");
        require(window>=0&&display>=0&&queued>=0&&deadline>0&&clock!=null,"action clock/window/display required");
        require((display==0&&generation==null)||(display>0&&generation!=null
                &&generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
                "action display generation required");
        long now=clock.elapsedRealtime();require(now>=queued,"action clock precedes queue sample");
        operationId=operation;taskId=task;modelRunId=run;observationId=observation;
        authorizationSha256=authorization;windowId=window;displayId=display;backgroundGeneration=generation;
        queuedElapsed=queued;deadlineElapsed=deadline;this.clock=clock;lastClockElapsed=now;
        append("queued",queued);
    }
    private static boolean id(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    private static void require(boolean value,String message){if(!value)throw new IllegalStateException(message);}
    private static void requirePhase(String phase){
        require(java.util.Arrays.asList("queued","snapshot_cloned","worker_started","scope_read","graph_read",
                "node_refresh","attempt_journal","effect_entered","effect_returned","readback","settle",
                "retired","worker_drained","callback_published").contains(phase),"fixed action phase required");
    }
    private static void requireReason(String reason){
        require("cancelled".equals(reason)||"deadline".equals(reason)||"lease_retired".equals(reason)
                ||"service_destroyed".equals(reason)||"controller_abandoned".equals(reason)||"queue_rejected".equals(reason),"fixed retirement reason required");
    }
    /** Sample only while the state monitor is held. Never clamp or reorder a bad clock. */
    private long sample(){
        long now=clock.elapsedRealtime();require(now>=queuedElapsed&&now>=lastClockElapsed,"action monotonic clock moved backwards");
        return now;
    }
    private void retireAt(String reason,long now){
        if(!retired){retired=true;retirementReason=reason;append("retired",now);}
        lastClockElapsed=now;
    }
    /** Calls contain no Android/Binder/file work and never acquire the process-wide slot lock. */
    public synchronized void check(boolean cancelled,boolean currentLease){
        long now=sample();
        if(!published){
            if(cancelled)retireAt("cancelled",now);
            else if(!currentLease)retireAt("lease_retired",now);
            else if(now>=deadlineElapsed)retireAt("deadline",now);
        }
        require(!retired&&!drained&&!published,"action unavailable");
        lastClockElapsed=now;
    }
    public synchronized void retire(String reason){
        requireReason(reason);
        // A late Stop cannot rewrite a receipt already handed to its original consumer.
        if(published)return;
        long now=sample();retireAt(reason,now);
    }
    /** Linearization point before the one real effect invocation, not proof of its completion. */
    public synchronized Map<String,Object> enterEffect(boolean cancelled,boolean currentLease){
        long now=sample();require(!effectEntered&&!drained&&!published,"action effect already entered or drained");
        if(cancelled)retireAt("cancelled",now);
        else if(!currentLease)retireAt("lease_retired",now);
        else if(now>=deadlineElapsed)retireAt("deadline",now);
        require(!retired,"action retired before effect");
        effectEntered=true;lastClockElapsed=now;return append("effect_entered",now);
    }
    /** A real return after retirement remains a fact; it does not renew authority. */
    public synchronized Map<String,Object> effectReturned(Boolean accepted){
        long now=sample();require(effectEntered&&!effectReturned&&!drained&&!published,"action effect return not current");
        effectReturned=true;apiAccepted=accepted;lastClockElapsed=now;return append("effect_returned",now);
    }
    public synchronized boolean effectEntered(){return effectEntered;}
    public synchronized boolean retired(){return retired;}
    public synchronized boolean isDrained(){return drained;}
    /** Executor finally after owned work returns, or a definitive rejection before execution. */
    public synchronized Map<String,Object> drained(){
        long now=sample();require(!drained&&!published,"action worker already drained");
        drained=true;drainedElapsed=now;lastClockElapsed=now;return append("worker_drained",now);
    }
    /** The main callback checks authority again after any delivery delay, without Binder or file IO. */
    public synchronized boolean publish(boolean cancelled,boolean currentLease){
        long now=sample();require(drained&&!published,"action callback not drained or already published");
        if(cancelled)retireAt("cancelled",now);
        else if(!currentLease)retireAt("lease_retired",now);
        else if(now>=deadlineElapsed)retireAt("deadline",now);
        publicationAllowed=!retired;published=true;lastClockElapsed=now;append("callback_published",now);return publicationAllowed;
    }
    public synchronized Map<String,Object> phase(String phase){
        requirePhase(phase);long now=sample();require(!drained&&!published,"action phase after drain");
        lastClockElapsed=now;return append(phase,now);
    }
    private Map<String,Object> append(String phase,long now){
        requirePhase(phase);
        if(phases.size()>=MAX_PHASES)phasesTruncated=true;
        else{Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("phase",phase);row.put("elapsed_ms",now);phases.add(row);}
        return marker(phase,now);
    }
    /** Both event and marker paths use the same finite vocabulary; this is diagnostic data only. */
    private Map<String,Object> marker(String phase,long now){
        requirePhase(phase);Map<String,Object> out=identity();out.put("schema","hepta.action-phase.v1");
        out.put("phase",phase);out.put("elapsed_ms",now);return out;
    }
    /** No OWNER, action payload, page text or node label is admitted. Never add this record to a model prompt. */
    public synchronized Map<String,Object> evidence(){
        Map<String,Object> out=identity();out.put("schema","hepta.action-execution.v1");
        out.put("execution_kind","serial_action_worker");out.put("clock_sampling","state_monitor_before_mutation");
        out.put("queued_clock_sampling","perform_entry_before_main_post");
        out.put("queued_elapsed_ms",queuedElapsed);out.put("deadline_elapsed_ms",deadlineElapsed);
        out.put("retired",retired);out.put("retirement_reason",retirementReason);
        out.put("effect_entered",effectEntered);out.put("effect_returned",effectReturned);out.put("api_accepted",apiAccepted);
        out.put("worker_drained",drained);out.put("worker_drained_elapsed_ms",drainedElapsed<0?null:Long.valueOf(drainedElapsed));
        out.put("callback_published",published);out.put("callback_authority_current",published?Boolean.valueOf(publicationAllowed):null);
        List<Map<String,Object>> copy=new ArrayList<Map<String,Object>>();
        for(Map<String,Object> phase:phases)copy.add(new LinkedHashMap<String,Object>(phase));
        out.put("phases",copy);out.put("phases_truncated",phasesTruncated);
        out.put("complete_phase_coverage",false);out.put("automatic_redispatch",false);return out;
    }
    private Map<String,Object> identity(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("operation_id",operationId);out.put("task_id",taskId);
        out.put("model_run_id",modelRunId);out.put("observation_id",observationId);out.put("authorization_sha256",authorizationSha256);
        out.put("window_id",windowId);out.put("display_id",displayId);out.put("background_generation",backgroundGeneration);return out;
    }

    /** After acquisition the owner must enqueue or run definitive rejection cleanup, even if cancellation races. */
    public static final class Slot {
        private ActionExecutionState active;
        public synchronized boolean acquire(ActionExecutionState work){
            require(work!=null,"action work required");if(active!=null)return false;
            synchronized(work){
                long now=work.sample();
                if(work.retired||work.drained||work.published)return false;
                if(now>=work.deadlineElapsed){work.retireAt("deadline",now);return false;}
                work.lastClockElapsed=now;active=work;return true;
            }
        }
        public synchronized boolean pending(){return active!=null;}
        public synchronized void release(ActionExecutionState work){
            require(active==work&&work!=null&&work.isDrained(),"only the physically drained owner may release the action slot");active=null;
        }
    }
}
