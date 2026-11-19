package org.trillionnium.hepta.background;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** One non-renewable screen lease for the actual isolated display returned to this broker.
 * The port never offers a global wake lock or a wake-up operation. Retiring the screen lease
 * does not prove task/display cleanup, and does not release a retained display custodian. */
final class PublicOwnGroupScreenLease {
    static final int SCREEN_BRIGHT = 0x0000000a;
    static final long MAX_LIFETIME_MS = 600000;
    interface Clock { long now(); }
    interface InitialWait { void pause(long millis) throws Exception; }
    interface Port {
        Snapshot read() throws Exception;
        void acquire(int flags, int displayId, long remainingMillis) throws Exception;
        boolean held();
        void release() throws Exception;
    }
    /** A fresh actual framework census. It is not deserialized from an App receipt. */
    static final class Snapshot {
        final int id, type, flags, ownerUid, group, mainGroup, coverGroup, groupMembers, state;
        final String name, uniqueId, ownerPackage;
        final boolean valid;
        Snapshot(int id, int type, int flags, int uid, int group, int mainGroup, int coverGroup,
                int groupMembers, int state, String name, String unique, String pkg, boolean valid) {
            this.id=id;this.type=type;this.flags=flags;ownerUid=uid;this.group=group;
            this.mainGroup=mainGroup;this.coverGroup=coverGroup;this.groupMembers=groupMembers;
            this.state=state;this.name=name;uniqueId=unique;ownerPackage=pkg;this.valid=valid;
        }
        void requireIsolatedIdentity(String generation) throws IOException {
            need(valid&&id>1&&type==5&&ownerUid==0&&"com.android.shell".equals(ownerPackage)
                    &&("hepta-bg-"+generation).equals(name)&&uniqueId!=null&&!uniqueId.isEmpty(),
                    "PUBLIC_SCREEN_IDENTITY_INVALID");
            need(flags==7040&&group>0&&mainGroup>=0&&coverGroup>=0&&group!=mainGroup
                    &&group!=coverGroup&&groupMembers==1,"PUBLIC_SCREEN_GROUP_NOT_ISOLATED");
        }
        void requireIsolatedOn(String generation) throws IOException {
            requireIsolatedIdentity(generation);
            need(state==2,"PUBLIC_SCREEN_NOT_ON");
        }
        boolean same(Snapshot other) {
            return other!=null&&id==other.id&&type==other.type&&flags==other.flags&&ownerUid==other.ownerUid
                    &&group==other.group&&mainGroup==other.mainGroup&&coverGroup==other.coverGroup
                    &&name.equals(other.name)&&uniqueId.equals(other.uniqueId)&&ownerPackage.equals(other.ownerPackage);
        }
    }

    private final String generation;
    private final long deadline;
    private final Clock clock;
    private final Object apiGate=new Object();
    private final AtomicBoolean started=new AtomicBoolean(), retired=new AtomicBoolean(), releaseWorker=new AtomicBoolean();
    private volatile Port port;
    private volatile Snapshot first;
    private volatile boolean acquireEntered, acquireReturned, active, releaseEntered, releaseReturned;
    private volatile long acquiredAt, releasedAt;
    private volatile String failure;
    private volatile long initialStartedAt,initialDeadline,initialReadyAt;
    private volatile int initialReads,initialFirstState=-1,initialLastState=-1;
    private volatile Snapshot initialIdentity;

    PublicOwnGroupScreenLease(String generation,long deadline,Clock clock) throws IOException {
        need(generation!=null&&generation.matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")&&clock!=null,
                "PUBLIC_SCREEN_LEASE_IDENTITY_INVALID");
        long now=clock.now();
        need(now>=0&&deadline>now&&deadline-now<=MAX_LIFETIME_MS,"PUBLIC_SCREEN_LEASE_DEADLINE_INVALID");
        this.generation=generation;this.deadline=deadline;this.clock=clock;
    }

    void acquire(Port actual) throws Exception { acquire(actual,0,null); }

    /** Only the new create request may wait for automatic initial UNKNOWN/OFF -> ON.
     * The caller freezes this deadline before create and never exceeds its original RPC budget. */
    void acquireInitiallyOn(Port actual,long initializationDeadline,InitialWait wait) throws Exception {
        need(wait!=null,"PUBLIC_SCREEN_INITIAL_WAIT_UNAVAILABLE");
        acquire(actual,initializationDeadline,wait);
    }

    private void acquire(Port actual,long initializationDeadline,InitialWait wait) throws Exception {
        need(actual!=null&&started.compareAndSet(false,true),"PUBLIC_SCREEN_LEASE_ALREADY_ATTEMPTED");
        port=actual;
        try {
            synchronized(apiGate) {
                requireLive();
                if(wait!=null)awaitInitialOn(actual,initializationDeadline,wait);
                // The original acquire still takes its own fresh, strictly ON census.
                Snapshot before=actual.read();before.requireIsolatedOn(generation);
                if(wait!=null){
                    need(initialIdentity.same(before),"PUBLIC_SCREEN_INITIAL_IDENTITY_CHANGED");
                    requireInitialBudget();
                }
                first=before;
                requireLive();
                long remaining=deadline-clock.now();
                need(remaining>0&&remaining<=MAX_LIFETIME_MS,"PUBLIC_SCREEN_LEASE_DEADLINE_INVALID");
                acquireEntered=true;
                actual.acquire(SCREEN_BRIGHT,before.id,remaining);
                acquireReturned=true;
                requireLive();
                if(wait!=null)requireInitialBudget();
                Snapshot after=actual.read();after.requireIsolatedOn(generation);
                need(before.same(after)&&actual.held(),"PUBLIC_SCREEN_ACQUIRE_NOT_CONFIRMED");
                requireLive();
                if(wait!=null)requireInitialBudget();
                acquiredAt=clock.now();active=true;
            }
        } catch(Exception error) {
            failure=reason(error);retire();throw error;
        } finally {
            // A cleanup racing a blocked acquire cannot release first and leave a late lock alive.
            // Both API calls serialize here, while the retirement latch never waits on this gate.
            if(retired.get())releaseNow();
        }
    }

    private void awaitInitialOn(Port actual,long initializationDeadline,InitialWait wait) throws Exception {
        initialStartedAt=clock.now();initialDeadline=initializationDeadline;
        need(initialStartedAt>=0&&initialDeadline>initialStartedAt&&initialDeadline-initialStartedAt<=5000
                &&initialDeadline<=deadline,"PUBLIC_SCREEN_INITIAL_DEADLINE_INVALID");
        long previous=initialStartedAt;
        while(true){
            requireLive();requireInitialBudget();
            long begin=clock.now();
            need(begin>=previous&&initialReads<201,"PUBLIC_SCREEN_INITIAL_CENSUS_BOUND");
            Snapshot current=actual.read();
            need(current!=null,"PUBLIC_SCREEN_INITIAL_CENSUS_UNAVAILABLE");
            if(initialReads++==0)initialFirstState=current.state;
            initialLastState=current.state;
            current.requireIsolatedIdentity(generation);
            if(initialIdentity==null)initialIdentity=current;
            else need(initialIdentity.same(current),"PUBLIC_SCREEN_INITIAL_IDENTITY_CHANGED");
            long now=clock.now();
            need(now>=begin,"PUBLIC_SCREEN_INITIAL_CLOCK_REVERSED");
            requireLive();requireInitialBudget();
            if(current.state==2){initialReadyAt=now;return;}
            need(current.state==0||current.state==1,"PUBLIC_SCREEN_INITIAL_STATE_REFUSED");
            previous=now;
            wait.pause(Math.min(25L,initialDeadline-now));
        }
    }

    private void requireInitialBudget() throws IOException {
        long now=clock.now();
        need(now>=initialStartedAt&&now<initialDeadline,"PUBLIC_SCREEN_INITIAL_DEADLINE_EXPIRED");
    }

    void requireActive() throws Exception {
        try {
            requireLive();
            Port actual=port;Snapshot expected=first;
            need(active&&actual!=null&&expected!=null&&acquireReturned&&actual.held(),"PUBLIC_SCREEN_LEASE_NOT_HELD");
            Snapshot current=actual.read();current.requireIsolatedOn(generation);
            need(expected.same(current),"PUBLIC_SCREEN_LIFETIME_IDENTITY_CHANGED");
            requireLive();
        } catch(Exception error) { failure=reason(error);retire();throw error; }
    }

    private void requireLive() throws IOException {
        long now=clock.now();
        need(!retired.get()&&now>=0&&now<deadline,"PUBLIC_SCREEN_LEASE_RETIRED");
    }

    /** Called by the independent broker watchdog, including before any retained-custodian return. */
    void observeDeadline(long now) { if(now>=deadline)retire(); }

    void retire() {
        retired.set(true);active=false;
        if(!started.get()||!releaseWorker.compareAndSet(false,true))return;
        try {
            Thread worker=new Thread(this::releaseNow,"HeptaPublicScreenRelease");
            worker.setDaemon(true);worker.start();
        } catch(Throwable error) { failure=reason(error); }
    }

    private void releaseNow() {
        synchronized(apiGate) {
            if(releaseReturned||releaseEntered)return;
            Port actual=port;
            if(actual==null||!acquireEntered)return;
            try {
                releaseEntered=true;
                // Even an acquire that threw can have entered Binder. Release only its exact token.
                actual.release();
                if(actual.held())throw new IOException("PUBLIC_SCREEN_RELEASE_NOT_CONFIRMED");
                releaseReturned=true;releasedAt=clock.now();
            } catch(Throwable error) { failure=reason(error); }
        }
    }

    Map<String,Object> evidence() {
        Map<String,Object> out=new LinkedHashMap<String,Object>();Snapshot bound=first==null?initialIdentity:first;
        out.put("schema","hepta.public-own-group.screen-lease.v1");out.put("generation",generation);
        out.put("display_id",bound==null?-1:bound.id);out.put("display_group_id",bound==null?-1:bound.group);
        out.put("wake_lock_flags",SCREEN_BRIGHT);out.put("expires_elapsed_ms",deadline);
        out.put("acquire_entered",acquireEntered);out.put("acquire_returned",acquireReturned);
        out.put("acquired_elapsed_ms",acquiredAt);out.put("admission_retired",retired.get());
        out.put("release_entered",releaseEntered);out.put("release_returned",releaseReturned);
        out.put("released_elapsed_ms",releasedAt);out.put("failure",failure);
        out.put("initial_readiness_started_elapsed_ms",initialStartedAt);
        out.put("initial_readiness_deadline_elapsed_ms",initialDeadline);
        out.put("initial_readiness_census_count",initialReads);
        out.put("initial_first_display_state",initialFirstState);out.put("initial_last_display_state",initialLastState);
        out.put("initial_on_observed_elapsed_ms",initialReadyAt);
        // Screen power is neither owned-task absence nor a business completion receipt.
        out.put("grants_cleanup_or_business_success",false);
        return out;
    }
    private static void need(boolean ok,String reason) throws IOException { if(!ok)throw new IOException(reason); }
    private static String reason(Throwable error) { String text=error.getMessage();return text==null?error.getClass().getSimpleName():text; }
}
