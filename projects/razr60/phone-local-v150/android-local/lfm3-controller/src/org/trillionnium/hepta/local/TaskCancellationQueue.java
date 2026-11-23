package org.trillionnium.hepta.local;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;

/** One captured task cancellation request; signal return, worker drain and native cleanup are separate facts. */
public final class TaskCancellationQueue {
    private static final TaskCancellationQueue PROCESS=new TaskCancellationQueue(java.util.concurrent.Executors.newSingleThreadExecutor());
    static TaskCancellationQueue processQueue(){return PROCESS;}
    /** A short identity/flag read only. Implementations must never do Binder, file, native or blocking work. */
    public interface Lease { boolean current(String identityId); }
    private final Executor executor;
    private final AtomicReference<Work> active=new AtomicReference<Work>();
    private final Object admission=new Object();
    /** Shared only with short process/task admission CAS operations; never with native or filesystem work. */
    Object admissionMonitor(){return admission;}

    /** The supplied executor must enqueue asynchronously; production uses its own single worker, never a caller-runs policy. */
    public TaskCancellationQueue(Executor executor){
        if(executor==null)throw new IllegalArgumentException("cancellation executor required");this.executor=executor;
    }
    public static final class Ticket {
        public final String taskId;
        public final String runId;
        private final String identityId;
        private final Object owner;
        private boolean requested,nativeCleanupKnown;
        private Work work;
        public Ticket(Object owner,String taskId){
            this(owner,taskId,false);
        }
        public static Ticket forRun(Object owner,String runId){return new Ticket(owner,runId,true);}
        private Ticket(Object owner,String identity,boolean run){
            if(owner==null||identity==null||!identity.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("captured owner/identity required");
            this.owner=owner;identityId=identity;taskId=run?null:identity;runId=run?identity:null;
        }
        public boolean ownedBy(Object expected){return owner==expected;}
        /** Called only with the real inference cleanup proof; false never erases an earlier true observation. */
        public synchronized void observeNativeCleanup(boolean known){if(known)nativeCleanupKnown=true;}
        /** Controller-worker only. The Stop/UI caller never waits here. */
        public boolean awaitDrain(long millis)throws InterruptedException{
            if(millis<0)throw new IllegalArgumentException("nonnegative drain budget required");
            Work value;synchronized(this){value=work;}
            return value==null||value.drainedSignal.await(millis,java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        public synchronized Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema","hepta.native-cancel-work.v1");
            out.put("task_id",taskId);out.put("request_reserved",requested);out.put("native_cleanup_known",nativeCleanupKnown);
            out.put("identity_kind",runId==null?"task":"run");out.put("run_id",runId);
            out.put("automatic_requeue",false);out.put("native_exit_proved_by_this_record",false);
            Work value=work;
            if(value==null){
                out.put("executor_accepted",false);out.put("worker_started",false);out.put("signal_entered",false);
                out.put("signal_returned",false);out.put("worker_drained",false);out.put("queue_rejected",false);
                out.put("submission_unknown",false);
                out.put("skipped_after_cleanup",false);out.put("skipped_after_lease_retired",false);out.put("error_class",null);
            }else synchronized(value){
                out.put("executor_accepted",value.accepted);out.put("worker_started",value.started);
                out.put("signal_entered",value.signalEntered);out.put("signal_returned",value.signalReturned);
                out.put("worker_drained",value.drained);out.put("queue_rejected",value.rejected);
                out.put("submission_unknown",value.submissionUnknown);
                out.put("skipped_after_cleanup",value.skippedCleanup);out.put("skipped_after_lease_retired",value.skippedLease);
                out.put("error_class",value.errorClass);
            }
            return out;
        }
    }
    private static final class Work {
        final Ticket ticket;
        final java.util.concurrent.CountDownLatch drainedSignal=new java.util.concurrent.CountDownLatch(1);
        boolean accepted,started,signalEntered,signalReturned,drained,rejected,submissionUnknown,skippedCleanup,skippedLease;
        String errorClass;
        Work(Ticket ticket){this.ticket=ticket;}
    }
    public boolean pending(){return active.get()!=null;}

    /** Reserves capacity under the same short monitor as native-cleanup observation, then submits without that monitor. */
    public boolean request(final Ticket ticket,final Lease lease,final Runnable signal){
        if(ticket==null||lease==null||signal==null)throw new IllegalArgumentException("captured cancellation inputs required");
        final Work work;
        synchronized(admission){
            synchronized(ticket){
                if(ticket.requested||ticket.nativeCleanupKnown)return false;
                ticket.requested=true;work=new Work(ticket);ticket.work=work;
                if(!active.compareAndSet(null,work)){
                    synchronized(work){work.rejected=true;work.drained=true;work.errorClass="cancellation_slot_busy";}
                    work.drainedSignal.countDown();
                    return false;
                }
            }
        }
        try{
            executor.execute(new Runnable(){public void run(){
                boolean enter=false;
                try{
                    // Only flags and the captured lease identity are read while holding the ticket monitor.
                    synchronized(ticket){
                        synchronized(work){work.accepted=true;work.started=true;}
                        if(ticket.nativeCleanupKnown){synchronized(work){work.skippedCleanup=true;}}
                        else if(!lease.current(ticket.identityId)){synchronized(work){work.skippedLease=true;}}
                        else{synchronized(work){work.signalEntered=true;}enter=true;}
                    }
                    // Native cancellation and captured-handle cancellation are never inside a ticket/slot/handle lock.
                    if(enter){signal.run();synchronized(work){work.signalReturned=true;}}
                }catch(RuntimeException failure){
                    synchronized(work){work.errorClass=failure.getClass().getName();}
                }finally{
                    synchronized(work){work.drained=true;}
                    if(!active.compareAndSet(work,null))throw new IllegalStateException("cancellation slot ownership changed");
                    work.drainedSignal.countDown();
                }
            }});
            synchronized(work){work.accepted=true;}
            return true;
        }catch(RejectedExecutionException rejected){
            synchronized(work){work.rejected=true;work.drained=true;work.errorClass=rejected.getClass().getName();}
            if(!active.compareAndSet(work,null))throw new IllegalStateException("rejected cancellation no longer owns its slot");
            work.drainedSignal.countDown();
            return false;
        }catch(RuntimeException uncertainSubmission){
            // A non-rejection failure does not prove whether execute() enqueued work.
            // Keep its slot until a real worker finally, never throw native cancellation back through Stop.
            synchronized(work){work.submissionUnknown=true;work.errorClass=uncertainSubmission.getClass().getName();}
            return false;
        }
    }
}
