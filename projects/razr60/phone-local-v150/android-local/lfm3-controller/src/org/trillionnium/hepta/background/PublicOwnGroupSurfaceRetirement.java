package org.trillionnium.hepta.background;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** One-way shutdown bookkeeping, not display/task authority or a cleanup proof.
 * The broker supplies an adapter holding only its actual create-returned VD handle.
 * Blocking identity/Surface Binder calls never hold this object's state lock. */
final class PublicOwnGroupSurfaceRetirement {
    static final long DEADLINE_MS=1500;
    interface Clock { long now(); }
    interface ApiEntry { void beforeCall(); }
    interface OwnedSurface {
        /** Returns one of the two locally established provenance labels, or throws. */
        String prepare() throws Exception;
        void detach(ApiEntry entry) throws Exception;
    }
    private boolean requested,workerClaimed,lateWorkerClaimed,identityObserved,adapterEntered,apiAttempted,apiReturned,finished,timedOut;
    private int activeWorkers;
    private Object apiOwner;
    private long began,ended;
    private String phase="NOT_REQUESTED",identitySource="NONE",failure="";

    synchronized boolean request(long now){
        if(requested)return false;
        if(now<0)throw new IllegalArgumentException("PUBLIC_SURFACE_CLOCK_INVALID");
        requested=true;began=now;phase="REQUESTED_UNVERIFIED";return true;
    }
    synchronized boolean retired(){return requested;}
    synchronized boolean originalDetachCompleted(){return requested&&finished&&apiReturned&&!timedOut&&failure.isEmpty();}
    synchronized long deadlineElapsed(){return began+DEADLINE_MS;}
    private synchronized boolean claim(boolean late){
        if(!requested||apiAttempted||(late?lateWorkerClaimed:workerClaimed))return false;
        if(late)lateWorkerClaimed=true;else workerClaimed=true;
        activeWorkers++;finished=false;if(!timedOut)phase="IDENTITY_READ_UNVERIFIED";return true;
    }
    synchronized void observeDeadline(long now){
        if(requested&&!finished&&now-began>=DEADLINE_MS){timedOut=true;phase="DEADLINE_UNVERIFIED";}
    }
    synchronized void workerUnavailable(Throwable error,long now){
        observeDeadline(now);failure=error.getClass().getName();
        if(!timedOut&&!apiAttempted)phase="WORKER_UNAVAILABLE_UNVERIFIED";
        if(activeWorkers==0){ended=now;finished=true;}
    }
    void run(OwnedSurface owned,Clock clock){run(owned,clock,false);}
    /** Called only when the broker's actual create API returns after closing.
     * It can request shutdown once; it cannot clear an earlier deadline or admit input. */
    void runLateCreated(OwnedSurface owned,Clock clock){run(owned,clock,true);}
    private void run(OwnedSurface owned,Clock clock,boolean late){
        if(!claim(late))return;
        final Object worker=new Object();
        try{
            if(owned==null||clock==null)throw new IllegalStateException("OWNED_HANDLE_UNAVAILABLE");
            final String source=owned.prepare();
            synchronized(this){
                observeDeadline(clock.now());
                if(!"FROZEN_FRAMEWORK_IDENTITY".equals(source)&&!"CREATE_RETURNED_HANDLE_ONLY".equals(source))
                    throw new IllegalStateException("OWNED_HANDLE_PROVENANCE_UNKNOWN");
                if(late&&!"CREATE_RETURNED_HANDLE_ONLY".equals(source))throw new IllegalStateException("LATE_CREATE_HANDLE_PROVENANCE_UNKNOWN");
                if(apiAttempted)return;
                if(timedOut&&!"CREATE_RETURNED_HANDLE_ONLY".equals(source))return;
                identitySource=source;identityObserved=true;adapterEntered=true;if(!timedOut)phase="ADAPTER_ENTERED_UNVERIFIED";
            }
            owned.detach(()->{
                synchronized(PublicOwnGroupSurfaceRetirement.this){
                    observeDeadline(clock.now());
                    if(apiAttempted)throw new IllegalStateException("DUPLICATE_SURFACE_DETACH_REFUSED");
                    if(timedOut&&!"CREATE_RETURNED_HANDLE_ONLY".equals(source))throw new IllegalStateException("SURFACE_IDENTITY_READ_DEADLINE");
                    apiOwner=worker;apiAttempted=true;identitySource=source;if(!timedOut)phase="DETACH_CALL_UNVERIFIED";
                }
            });
            synchronized(this){
                if(apiOwner!=worker)throw new IllegalStateException("SURFACE_API_ENTRY_NOT_OBSERVED");
                apiReturned=true;observeDeadline(clock.now());if(!timedOut)phase="API_RETURNED_UNVERIFIED";
            }
        }catch(Throwable error){
            synchronized(this){if(apiOwner==null||apiOwner==worker){failure=error.getClass().getName();
                if(!timedOut)phase=apiAttempted?"API_FAILED_UNVERIFIED":"IDENTITY_UNAVAILABLE_UNVERIFIED";}}
        }finally{
            synchronized(this){ended=clock==null?began:clock.now();observeDeadline(ended);activeWorkers--;finished=activeWorkers==0;}
        }
    }
    synchronized Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.public-own-group.surface-retirement.v1");out.put("admission_irrevocably_retired",requested);
        out.put("state",phase);out.put("worker_claimed",workerClaimed);out.put("late_create_worker_claimed",lateWorkerClaimed);
        out.put("identity_read_completed",identityObserved);out.put("adapter_entered",adapterEntered);
        out.put("identity_source",identitySource);out.put("api_attempted",apiAttempted);out.put("api_returned",apiReturned);
        out.put("began_elapsed_ms",began);out.put("ended_elapsed_ms",ended);out.put("worker_finished",finished);
        out.put("deadline_exceeded",timedOut);out.put("failure_type",failure);
        out.put("surface_stopped_verified",false);out.put("provides_task_or_display_cleanup_proof",false);
        out.put("allows_input_or_model_resumption",false);
        out.put("shutdown_depends_on_fresh_display_binder_query",false);
        return Collections.unmodifiableMap(out);
    }
}
