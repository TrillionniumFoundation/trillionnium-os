package org.trillionnium.hepta.background;

/** Monotonic lifecycle gate shared by normal cleanup, watchdog, main and shutdown hook. */
final class ProfileDisplayCustody {
    private boolean attempted,tasksClear,displayAbsent,unknown;
    synchronized void beforeCreate(){attempted=true;}
    synchronized void tasksVerified(){if(!unknown)tasksClear=true;}
    synchronized boolean mayRelease(){return tasksClear&&!unknown;}
    synchronized void unresolved(){unknown=true;}
    synchronized void displayVerifiedAbsent(){
        if(!tasksClear||unknown)throw new IllegalStateException("PROFILE_CUSTODY_NOT_RELEASEABLE");
        displayAbsent=true;
    }
    synchronized boolean retain(){return attempted&&!displayAbsent;}
    synchronized boolean known(){return tasksClear&&displayAbsent&&!unknown;}
}
