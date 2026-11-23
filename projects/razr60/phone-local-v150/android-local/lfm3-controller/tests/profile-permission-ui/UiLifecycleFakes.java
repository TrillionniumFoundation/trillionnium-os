package org.trillionnium.hepta.local;

import org.trillionnium.hepta.background.PermissionWindowObservation;
import org.trillionnium.hepta.background.UiPermissionFixture;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Explicit inert dependency substitutes for the real UiSession concurrency
 * test. These are not shipped or counted as Android integration qualification. */
final class HeptaAccessibilityService {
    interface Cancellation { boolean isCancelled(); }
    volatile boolean current=true;
    boolean permissionInitializationCurrent(String id,QualificationScopeConfig.Bound scope,TaskAuthorization.Gate gate,BackgroundSession bg){return current;}
    void requirePermissionInitializationCurrent(String id,QualificationScopeConfig.Bound scope,TaskAuthorization.Gate gate,
            BackgroundSession bg,Cancellation cancel,long deadline){
        if(!current||cancel.isCancelled()||android.os.SystemClock.elapsedRealtime()>=deadline)throw new IllegalStateException("captured task retired");
        bg.requirePermissionPreparationActive();
    }
    static String message(Throwable error){return error.getMessage()==null?error.getClass().getSimpleName():error.getMessage();}
    static String sha(byte[] bytes)throws Exception{
        StringBuilder b=new StringBuilder();for(byte value:MessageDigest.getInstance("SHA-256").digest(bytes))b.append(String.format("%02x",value&255));return b.toString();
    }
}
final class QualificationScopeConfig {static final class Bound {}}
final class TaskAuthorization {static final class Gate {}}
final class MobiMindPrivateFiles {
    static volatile String failLeaf;
    static void writeNew(File file,byte[] bytes)throws Exception{
        if(file.getName().equals(failLeaf))throw new IOException("synthetic durable-write failure");
        try(java.nio.channels.FileChannel channel=java.nio.channels.FileChannel.open(file.toPath(),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){
            java.nio.ByteBuffer content=java.nio.ByteBuffer.wrap(bytes);while(content.hasRemaining())channel.write(content);channel.force(true);
        }
    }
}
final class BackgroundSession {
    final String ownerSha256;
    final UiPermissionFixture fixture;
    final IdentityHashMap<PermissionWindowObservation,Boolean> received=new IdentityHashMap<PermissionWindowObservation,Boolean>();
    final AtomicInteger reads=new AtomicInteger(),observations=new AtomicInteger(),clicks=new AtomicInteger(),closedAdapters=new AtomicInteger();
    final ConcurrentLinkedQueue<String> confirmations=new ConcurrentLinkedQueue<String>();
    final ConcurrentLinkedQueue<String> sampled=new ConcurrentLinkedQueue<String>();
    final AtomicInteger confirmationCalls=new AtomicInteger();
    volatile boolean advanceWaiting;
    volatile String state="PERMISSION_PENDING";
    volatile boolean location=true,active=true,accepted=true;
    volatile CountDownLatch readEntered,releaseRead,beforeInput,releaseInput,afterEntered,releaseEntered;
    BackgroundSession(String dump,String ownerSha)throws Exception{fixture=new UiPermissionFixture(dump);ownerSha256=ownerSha;}
    void requirePermissionPreparationActive(){if(!active)throw new IllegalStateException("profile preparation retired");}
    String readPreparation(HeptaAccessibilityService.Cancellation cancel,long deadline)throws Exception{
        reads.incrementAndGet();CountDownLatch entered=readEntered,release=releaseRead;
        if(entered!=null){entered.countDown();if(release!=null)release.await();}
        String scripted=sampled.poll();
        if(scripted!=null)state=scripted;
        if(advanceWaiting&&"WAITING".equals(state)){advanceWaiting=false;state="APP_READY";return "WAITING";}
        return state;
    }
    String confirmPermissionPreparation(HeptaAccessibilityService.Cancellation cancel,long deadline){
        requirePermissionPreparationActive();confirmationCalls.incrementAndGet();
        if(cancel.isCancelled()||android.os.SystemClock.elapsedRealtime()>=deadline||!"APP_READY".equals(state))
            throw new IllegalStateException("invalid synthetic confirmation request");
        String answer=confirmations.poll();if(answer==null)answer="COMPLETE";
        if("COMPLETE".equals(answer))active=false;else state=answer;
        return answer;
    }
    void requirePermissionWindow(PermissionWindowObservation proof,long now){
        requirePermissionPreparationActive();if(!received.containsKey(proof))throw new IllegalStateException("not a current synthetic RPC object");proof.requireFresh(now);
    }
}
final class ProfilePermissionAndroidAdapter implements AutoCloseable {
    interface Guard { void check()throws Exception;void authority()throws Exception; }
    final BackgroundSession bg;final Guard guard;
    ProfilePermissionAndroidAdapter(HeptaAccessibilityService service,BackgroundSession bg,HeptaAccessibilityService.Cancellation cancel,long deadline,Guard guard){
        this.bg=bg;this.guard=guard;
    }
    ProfilePermissionInitialization.Snapshot observe()throws Exception{
        guard.check();bg.observations.incrementAndGet();ProfilePermissionInitialization.Snapshot snapshot=bg.fixture.snapshot(bg.location,android.os.SystemClock.elapsedRealtime());
        bg.received.put(snapshot.identity,Boolean.TRUE);return snapshot;
    }
    boolean clickOrdinaryDeny(ProfilePermissionInitialization.Dispatch dispatch)throws Exception{
        if(bg.beforeInput!=null){bg.beforeInput.countDown();if(bg.releaseInput!=null)bg.releaseInput.await();}
        ProfilePermissionInitialization.Node actual=dispatch.enter(observe());
        if(!ProfilePermissionInitialization.DENY.equals(actual.resourceId))throw new AssertionError("non-deny input");
        guard.check();bg.clicks.incrementAndGet();
        if(bg.afterEntered!=null){bg.afterEntered.countDown();if(bg.releaseEntered!=null)bg.releaseEntered.await();}
        bg.state="APP_READY";return bg.accepted;
    }
    public void close(){bg.closedAdapters.incrementAndGet();}
}
