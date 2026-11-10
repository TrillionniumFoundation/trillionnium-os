package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Parent observations only. A destroy invocation is not proof of signal delivery,
 * and an exit observation is not the time or cause of the child's actual exit.
 */
public final class WarmProcessTimeline {
    public enum Source {
        OWNER_HANDLE_CANCEL, REQUEST_HANDLE_CANCEL, SESSION_CANCEL,
        REQUEST_DEADLINE, REQUEST_FAILURE, CLOSE_WRITE_FAILURE, NON_GRACEFUL_CLOSE,
        CLOSE_WAIT_EXPIRED, TERMINATION, FORCE_WAIT_EXPIRED, FALLBACK_CLOSE,
        ENGINE_FAILURE, REQUEST_WAIT, GRACEFUL_CLOSE_WAIT, TERMINATION_WAIT,
        FALLBACK_WAIT, ENGINE_WAIT, ENGINE_EXIT_VALUE
    }
    private final String generation, taskId;
    private final long originNanos=System.nanoTime();
    private Map<String,Object> cancel, destroy, force, exit;
    private int eventSequence, destroyCalls, forceCalls;

    public WarmProcessTimeline(String generation,String taskId) {
        if(generation==null||!generation.matches("[0-9a-f]{32}")
                ||taskId==null||!taskId.matches("[0-9a-f]{32}"))
            throw new IllegalArgumentException("exact task/generation required");
        this.generation=generation;this.taskId=taskId;
    }
    void requireOwner(String expectedGeneration,String expectedTask) {
        if(!generation.equals(expectedGeneration)||!taskId.equals(expectedTask))
            throw new IllegalArgumentException("parent timeline belongs to another task/generation");
    }
    private long elapsedNanos(){return System.nanoTime()-originNanos;}
    private Map<String,Object> event(Source source,Integer exitCode) {
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("elapsed_ns",Long.valueOf(elapsedNanos()));
        value.put("sequence",Integer.valueOf(++eventSequence));
        value.put("source",source.name().toLowerCase(Locale.ROOT));
        if(exitCode!=null)value.put("exit_code",exitCode);
        return Collections.unmodifiableMap(value);
    }
    public synchronized void cancelRequested(Source source) {
        if(cancel==null)cancel=event(source,null);
    }
    public void destroy(Process process,Source source) {
        synchronized(this){destroyCalls++;if(destroy==null)destroy=event(source,null);}
        process.destroy();
    }
    public void destroyForcibly(Process process,Source source) {
        synchronized(this){forceCalls++;if(force==null)force=event(source,null);}
        process.destroyForcibly();
    }
    public synchronized void exitObserved(int exitCode,Source source) {
        if(exit==null)exit=event(source,Integer.valueOf(exitCode));
    }
    /** An immutable snapshot; calls after this snapshot are not retroactively included. */
    public synchronized Map<String,Object> snapshot() {
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("schema","hepta.parent-process-timeline.v1");
        value.put("worker_generation",generation);value.put("task_id",taskId);
        value.put("clock","System.nanoTime");value.put("units","nanoseconds");
        value.put("origin","parent_warm_task_timeline_creation");
        value.put("clock_scope","same_parent_process_only");
        value.put("snapshot_elapsed_ns",Long.valueOf(elapsedNanos()));
        value.put("first_cancel_requested",cancel);
        value.put("first_destroy_invoked",destroy);
        value.put("first_destroy_forcibly_invoked",force);
        value.put("first_exit_observed",exit);
        value.put("destroy_invocation_count",Integer.valueOf(destroyCalls));
        value.put("destroy_forcibly_invocation_count",Integer.valueOf(forceCalls));
        value.put("signal_delivery_proven",Boolean.FALSE);
        value.put("exit_cause_inferred",Boolean.FALSE);
        return Collections.unmodifiableMap(value);
    }
}
