package org.trillionnium.hepta.background;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/** One authenticated cleanup interval. This object has no launch/input API and
 * never resets either the business deadline or the original failure receipts. */
final class RetainedProfileCleanupAttempt {
    interface Work {ProfileOwnedTask.RetainedCleanupProof run(long deadline)throws Exception;}
    private final BrokerProtocol.Config config;
    private final LongSupplier clock;
    private BrokerProtocol.RetainedCleanupRequest request;
    private ProfileOwnedTask.RetainedCleanupProof proof;
    private boolean entered,finished;
    private String failure;
    private long finishedAt;
    RetainedProfileCleanupAttempt(BrokerProtocol.Config config,LongSupplier clock){
        if(config==null||clock==null)throw new IllegalArgumentException("RETAINED_CLEANUP_ATTEMPT_ARGUMENTS");
        this.config=config;this.clock=clock;
    }
    synchronized void claim(BrokerProtocol.RetainedCleanupRequest next,int peerUid)throws Exception{
        next.authenticate(config,peerUid,clock.getAsLong());
        if(request!=null)throw new BrokerProtocol.Refusal("RETAINED_CLEANUP_ALREADY_CLAIMED");
        request=next;
    }
    synchronized boolean claimed(){return request!=null;}
    void run(Work work)throws Exception{
        final long deadline;
        synchronized(this){
            if(request==null||entered||work==null)throw new BrokerProtocol.Refusal("RETAINED_CLEANUP_ALREADY_ENTERED");
            entered=true;deadline=request.deadline;
        }
        try{
            if(clock.getAsLong()>=deadline)throw new BrokerProtocol.Refusal("RETAINED_CLEANUP_DEADLINE");
            ProfileOwnedTask.RetainedCleanupProof result=work.run(deadline);
            if(result==null||clock.getAsLong()>=deadline)throw new BrokerProtocol.Refusal("RETAINED_CLEANUP_PROOF_LATE_OR_MISSING");
            synchronized(this){proof=result;}
        }catch(Exception error){synchronized(this){failure=error.getMessage()==null?error.getClass().getSimpleName():error.getMessage();}throw error;}
        finally{synchronized(this){finishedAt=clock.getAsLong();finished=true;}}
    }
    synchronized ProfileOwnedTask.RetainedCleanupProof completedProof(){return finished?proof:null;}
    synchronized Map<String,Object> evidence(){
        Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("schema","hepta.retained-profile-cleanup-attempt.v1");
        value.put("request",request==null?null:request.evidence());value.put("claimed",request!=null);value.put("entered",entered);
        value.put("finished",finished);value.put("finished_elapsed_ms",finishedAt);value.put("current_absence_verified",finished&&proof!=null);
        value.put("failure",failure);value.put("interval",proof==null?null:proof.evidence());
        value.put("business_admission_restored",false);value.put("business_deadline_extended",false);
        value.put("old_failure_rewritten",false);value.put("request_replayed",false);
        return Collections.unmodifiableMap(value);
    }
}
