package org.trillionnium.hepta.background;

/** Monotonic lifecycle gate shared by normal cleanup, watchdog, main and shutdown hook. */
final class ProfileDisplayCustody {
    private boolean attempted,tasksClear,displayAbsent,unknown,retainedObservedAbsent;
    synchronized void beforeCreate(){attempted=true;}
    synchronized void tasksVerified(){if(!unknown)tasksClear=true;}
    synchronized boolean mayRelease(){return tasksClear&&!unknown;}
    synchronized boolean normalCleanupAllowed(){return attempted&&!unknown&&!displayAbsent;}
    synchronized void unresolved(){unknown=true;}
    synchronized void displayVerifiedAbsent(){
        if(!tasksClear||unknown)throw new IllegalStateException("PROFILE_CUSTODY_NOT_RELEASEABLE");
        displayAbsent=true;
    }
    synchronized void retainedObservedAbsent(ProfileOwnedTask original){
        if(!attempted||!unknown||original==null||!original.retainedAbsenceVerified())
            throw new IllegalStateException("PROFILE_RETAINED_FINAL_PROOF_MISSING");
        retainedObservedAbsent=true;
    }
    synchronized void retainedCleanupObservedAbsent(ProfileOwnedTask original,ProfileOwnedTask.RetainedCleanupProof proof){
        if(!attempted||!unknown||original==null||!original.ownsRetainedCleanupProof(proof))
            throw new IllegalStateException("PROFILE_RETAINED_CLEANUP_PROOF_MISSING");
        // Unknown is the immutable business result. This only ends live custody
        // after a distinct cleanup interval has proved current absence.
        retainedObservedAbsent=true;
    }
    synchronized boolean retain(){return attempted&&!displayAbsent&&!retainedObservedAbsent;}
    synchronized boolean known(){return (tasksClear&&displayAbsent&&!unknown)||retainedObservedAbsent;}
}
