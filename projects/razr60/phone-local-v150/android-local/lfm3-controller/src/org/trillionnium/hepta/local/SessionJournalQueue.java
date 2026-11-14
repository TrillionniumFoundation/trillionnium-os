package org.trillionnium.hepta.local;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/** Serial durable writes, with a separate main-thread acknowledgement barrier.
 * The supplied IO executor is serial. No file operation or completion runs under gate.
 * An ambiguous executor submission never grants permission to start a task. */
final class SessionJournalQueue {
    interface Write { void run() throws Exception; }
    interface Completion { void finished(Result result); }
    interface Failure { void failed(Exception error); }
    static final int MAX_OUTSTANDING=64;
    static final class Result {
        final long sequence;
        final boolean writeInvoked, success;
        final Exception error;
        Result(long sequence,boolean invoked,boolean success,Exception error){
            this.sequence=sequence;this.writeInvoked=invoked;this.success=success;this.error=error;
        }
    }
    private static final class Job {
        final long sequence;final Write write;final Completion completion;final Failure failure;
        boolean started,exited,submissionResolved,submissionAccepted,deliveryReserved,applied,failureSignalled;
        Exception error;
        Job(long sequence,Write write,Completion completion,Failure failure){
            this.sequence=sequence;this.write=write;this.completion=completion;this.failure=failure;
        }
    }
    private final Object gate=new Object();
    private final Executor io,main;
    private long issued;
    private int outstanding;
    private boolean failed;

    SessionJournalQueue(Executor io,Executor main){
        if(io==null||main==null)throw new NullPointerException("journal executors");
        this.io=io;this.main=main;
    }
    boolean pending(){synchronized(gate){return outstanding!=0;}}
    boolean failed(){synchronized(gate){return failed;}}
    /** Only after the normal recovery transaction independently proved a new idle session. */
    void acknowledgedAfterVerifiedRecovery(){
        synchronized(gate){
            if(outstanding!=0)throw new IllegalStateException("journal work has not been acknowledged");
            failed=false;
        }
    }
    boolean submit(Write write,Completion completion){
        return submit(write,completion,null);
    }
    boolean submit(Write write,Completion completion,Failure failure){
        if(write==null||completion==null)throw new NullPointerException("journal work");
        final Job job;final boolean saturated;
        synchronized(gate){
            job=new Job(++issued,write,completion,failure);saturated=outstanding>=MAX_OUTSTANDING;
            if(saturated){failed=true;job.error=new RejectedExecutionException("session journal capacity exhausted");}
            else outstanding++;
        }
        if(saturated){signalFailure(job);return false;}
        try{
            io.execute(new Runnable(){public void run(){runWrite(job);}});
            synchronized(gate){job.submissionResolved=true;job.submissionAccepted=true;}
            offerDelivery(job);
            return true;
        }catch(RejectedExecutionException rejected){
            synchronized(gate){
                failed=true;job.error=rejected;job.submissionResolved=true;
                // Standard executors reject before invocation. If it nevertheless entered,
                // the real invocation still owns the barrier until it exits.
                if(!job.started)job.exited=true;
            }
            signalFailure(job);
            offerDelivery(job);
            return false;
        }catch(RuntimeException uncertain){
            synchronized(gate){failed=true;job.error=uncertain;job.submissionResolved=true;}
            signalFailure(job);
            // No invented exit, callback, retry, or clean state for an unknown submission.
            offerDelivery(job);
            return false;
        }
    }
    private void runWrite(Job job){
        synchronized(gate){
            if(job.started||job.exited)return;
            job.started=true;
        }
        Exception failure=null;
        try{job.write.run();}catch(Exception error){failure=error;}
        synchronized(gate){
            job.exited=true;
            if(failure!=null){failed=true;job.error=failure;}
        }
        if(failure!=null)signalFailure(job);
        offerDelivery(job);
    }
    private void signalFailure(Job job){
        final Failure hook;final Exception error;
        synchronized(gate){
            if(job.failureSignalled)return;
            job.failureSignalled=true;hook=job.failure;error=job.error;
        }
        // The production hook only sets a volatile barrier and stops its captured task.
        // Native cancellation itself remains on its separate owned worker.
        if(hook!=null)try{hook.failed(error);}catch(RuntimeException unavailable){synchronized(gate){failed=true;}}
    }
    private void offerDelivery(final Job job){
        synchronized(gate){
            if(!job.exited||!job.submissionResolved||job.deliveryReserved)return;
            job.deliveryReserved=true;
        }
        try{
            main.execute(new Runnable(){public void run(){
                final Result result;
                synchronized(gate){
                    if(job.applied)return;
                    job.applied=true;outstanding--;
                    result=new Result(job.sequence,job.started,
                            job.submissionAccepted&&job.started&&job.error==null,job.error);
                }
                try{job.completion.finished(result);}
                catch(RuntimeException unavailable){
                    synchronized(gate){failed=true;job.error=unavailable;}
                    signalFailure(job);
                }
            }});
        }catch(RuntimeException unavailable){
            // A lost UI acknowledgement cannot make the session appear idle.
            synchronized(gate){failed=true;job.error=unavailable;}
            signalFailure(job);
        }
    }
}
