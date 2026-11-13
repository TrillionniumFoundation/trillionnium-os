package org.trillionnium.hepta.local;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** One termination clock and signal authority for one actual task worker.
 * Cancellation is immediate; observed exit and successful SDK cleanup are separate facts.
 */
public final class OwnedWorkerCancellation {
    public static final long COOPERATIVE_GRACE_MILLIS=8000;
    // The pinned GenieX token callback is first invoked after full prefill. The
    // actual Qwen NPU cancellation needed an 11.8s prefill before that callback.
    // This fixed warm-NPU policy allows additional bounded time for prefill to drain;
    // it does not promise prompt interruption or restart/extend on another Stop.
    public static final long WARM_NPU_PREFILL_GRACE_MILLIS=30000;
    public static final long FORCE_OBSERVATION_MILLIS=8000;
    public static final long NORMAL_CLOSE_MILLIS=2000;
    public static final long FINISH_FUTURE_MILLIS=22000;
    private final long cooperativeGraceMillis,graceNanos,totalNanos;
    private final String policy;
    private static final long CLOSE_NANOS=TimeUnit.MILLISECONDS.toNanos(NORMAL_CLOSE_MILLIS);
    interface Clock { long nanoTime(); }
    private static final Clock SYSTEM_CLOCK=new Clock(){public long nanoTime(){return System.nanoTime();}};
    public final String generation,taskId;
    private final Clock clock;
    private final AtomicBoolean requested=new AtomicBoolean();
    private Process process;
    private boolean terminationStarted,closeStarted,termAttempted,termReturned,forceAttempted,forceReturned;
    private long terminationAt,closeAt;
    private Integer observedExit;
    private String signalError;

    public static final class Exit {
        public final boolean observed,forceSent;
        public final Integer code;
        private Exit(boolean observed,Integer code,boolean forceSent){this.observed=observed;this.code=code;this.forceSent=forceSent;}
    }
    public static final class Snapshot {
        public final String generation,taskId,signalError,policy;
        public final long cooperativeGraceMillis,finishFutureMillis;
        public final boolean requested,processBound,terminationStarted,termReturned,forceReturned,exitObserved;
        public final int termAttempts,forceAttempts;
        public final Integer exitCode;
        private Snapshot(OwnedWorkerCancellation value){
            generation=value.generation;taskId=value.taskId;signalError=value.signalError;
            policy=value.policy;cooperativeGraceMillis=value.cooperativeGraceMillis;finishFutureMillis=value.finishFutureMillis();
            requested=value.requested.get();processBound=value.process!=null;terminationStarted=value.terminationStarted;
            termAttempts=value.termAttempted?1:0;forceAttempts=value.forceAttempted?1:0;
            termReturned=value.termReturned;forceReturned=value.forceReturned;
            exitObserved=value.observedExit!=null;exitCode=value.observedExit;
        }
    }
    public OwnedWorkerCancellation(String generation,String taskId){this(generation,taskId,SYSTEM_CLOCK);}
    /** Only the immutable ordinary warm NPU configuration selects this policy. */
    public static OwnedWorkerCancellation forWarmNpu(String generation,String taskId){
        return forWarmNpu(generation,taskId,SYSTEM_CLOCK);
    }
    static OwnedWorkerCancellation forWarmNpu(String generation,String taskId,Clock clock){
        return new OwnedWorkerCancellation(generation,taskId,clock,WARM_NPU_PREFILL_GRACE_MILLIS,"warm_npu_prefill");
    }
    OwnedWorkerCancellation(String generation,String taskId,Clock clock){
        this(generation,taskId,clock,COOPERATIVE_GRACE_MILLIS,"default_owned_worker");
    }
    private OwnedWorkerCancellation(String generation,String taskId,Clock clock,long graceMillis,String policy){
        if(!id(generation)||!id(taskId)||clock==null)throw new IllegalArgumentException("exact task, generation and monotonic clock required");
        this.generation=generation;this.taskId=taskId;this.clock=clock;
        this.cooperativeGraceMillis=graceMillis;this.policy=policy;
        this.graceNanos=TimeUnit.MILLISECONDS.toNanos(graceMillis);
        this.totalNanos=TimeUnit.MILLISECONDS.toNanos(graceMillis+FORCE_OBSERVATION_MILLIS);
    }
    public long finishFutureMillis(){
        return FINISH_FUTURE_MILLIS+(cooperativeGraceMillis-COOPERATIVE_GRACE_MILLIS);
    }
    private static boolean id(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    /** The same Process may be rebound only to this same immutable task/generation. */
    public synchronized void attach(Process actual,String actualGeneration,String actualTask){
        if(actual==null||!generation.equals(actualGeneration)||!taskId.equals(actualTask)
                ||process!=null&&process!=actual)throw new IllegalArgumentException("foreign worker cancellation authority");
        process=actual;
        if(requested.get())signalOnce();
    }
    public boolean isCancellationRequested(){return requested.get();}
    public void cancel(){
        requested.set(true); // Never wait for SDK progress before preventing another request/tool.
        synchronized(this){if(process!=null)signalOnce();}
    }
    private void signalOnce(){
        if(!terminationStarted){terminationStarted=true;terminationAt=clock.nanoTime();}
        if(termAttempted||observedExit!=null||!process.isAlive())return;
        termAttempted=true; // A failed call is not silently retried by another Stop path.
        try{process.destroy();termReturned=true;}
        catch(RuntimeException error){signalError=error.getClass().getName()+": "+String.valueOf(error.getMessage());}
    }
    private synchronized Process owned(){
        if(process==null)throw new IllegalStateException("no actual worker attached");
        return process;
    }
    private synchronized Exit result(){return new Exit(observedExit!=null,observedExit,forceReturned);}
    private synchronized long elapsed(){return clock.nanoTime()-terminationAt;}
    private boolean waitObserved(Process actual,long nanos)throws InterruptedException{
        if(actual.waitFor(Math.max(0,nanos),TimeUnit.NANOSECONDS)){
            int value=actual.exitValue();
            synchronized(this){
                if(process!=actual||observedExit!=null&&observedExit.intValue()!=value)
                    throw new IllegalStateException("owned worker exit identity changed");
                observedExit=value;
            }
            return true;
        }
        return false;
    }
    private void forceOnce(Process actual){
        synchronized(this){
            if(process!=actual)throw new IllegalStateException("foreign worker");
            if(observedExit!=null||forceAttempted||!actual.isAlive())return;
            if(!terminationStarted||elapsed()<graceNanos)throw new IllegalStateException("force before shared grace deadline");
            forceAttempted=true;
            try{actual.destroyForcibly();forceReturned=true;}
            catch(RuntimeException error){signalError=error.getClass().getName()+": "+String.valueOf(error.getMessage());}
        }
    }
    /** Duplicate callers reuse the first signal's deadline and never resend a signal. */
    public Exit awaitCancellation(){
        cancel();Process actual=owned();
        try{
            if(result().observed)return result();
            long remaining=graceNanos-elapsed();
            if(waitObserved(actual,remaining))return result();
            // A Process implementation returning false early provides no right to shorten grace.
            if(elapsed()<graceNanos)return result();
            // Observe an exit already available at the boundary before escalating.
            // This reduces a race; it is not an atomic signal/exit guarantee.
            if(waitObserved(actual,0))return result();
            forceOnce(actual);
            if(waitObserved(actual,totalNanos-elapsed()))return result();
            return result(); // Actual lack of waitFor completion remains unknown.
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();return result();}
    }
    /** Only used after the owner actually sent its single CLOSE frame. */
    public Exit awaitGracefulClose(){
        Process actual=owned();long start;
        synchronized(this){if(!closeStarted){closeStarted=true;closeAt=clock.nanoTime();}start=closeAt;}
        try{
            if(result().observed)return result();
            if(!requested.get()&&waitObserved(actual,CLOSE_NANOS-(clock.nanoTime()-start)))return result();
            if(!requested.get()&&clock.nanoTime()-start<CLOSE_NANOS)return result();
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();cancel();return result();}
        return awaitCancellation();
    }
    public synchronized Snapshot snapshot(){return new Snapshot(this);}
}
