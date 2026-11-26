package org.trillionnium.hepta.background;

import android.app.ActivityOptions;
import android.content.Context;
import android.os.Binder;
import android.os.SystemClock;
import java.util.List;
import java.util.function.LongSupplier;

/** Privileged, read-back driven adapter for the dedicated managed-profile coordinator. */
final class ProfileTaskPlatform implements ProfileOwnedTask.Platform {
    private final Object activityTasks;
    private final ProfilePackages packages;
    private final ProfileTarget expected;
    private final BackgroundTaskOrganizer organizer;
    private final BackgroundTaskOrganizer.Check active;
    private final LongSupplier deadline;
    private volatile ProfilePackages.Readback last;
    private volatile java.util.Map<String,Object> firstPermissionReadMismatch=java.util.Collections.emptyMap();
    ProfileTaskPlatform(Object activityTasks,ActivityOptions options,int display,ProfilePackages packages,
            ProfileTarget expected,BackgroundTaskOrganizer.Check active,LongSupplier deadline)throws Exception {
        this.activityTasks=activityTasks;this.packages=packages;this.expected=expected;
        this.active=active;this.deadline=deadline;
        organizer=new BackgroundTaskOrganizer(activityTasks,options,display,active,()->recheck(false),deadline);
    }
    static ProfilePackages.Readback preflight(Object activityTasks,ProfilePackages packages,
            ProfileTarget expected,long deadline)throws Exception {
        ProfilePackages.Readback actual=packages.read(expected.profile.userId,expected.packageName,true,deadline);
        ProfileTaskPolicy.need(expected.same(actual.target),"PROFILE_INSTALLATION_IDENTITY_CHANGED");
        BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireDedicatedEmpty(actual.target);
        ProfileTaskPolicy.Recents.parse(BackgroundTaskOrganizer.profileRecents(()->deadline))
                .requireDedicatedEmpty(actual.target);
        return actual;
    }
    static ProfilePackages.Readback publicPreflight(Object activityTasks,ProfilePackages packages,
            ProfileTarget expected,long deadline)throws Exception {
        ProfilePackages.Readback actual=packages.read(expected.profile.userId,expected.packageName,true,deadline);
        ProfileTaskPolicy.need(expected.same(actual.target),"PROFILE_INSTALLATION_IDENTITY_CHANGED");
        BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireDedicatedEmpty(actual.target);
        return actual;
    }
    @Override public ProfileTarget recheck(boolean ready)throws Exception {
        ProfilePackages.Readback actual=packages.read(expected.profile.userId,expected.packageName,ready,deadline.getAsLong());
        ProfileTaskPolicy.need(expected.same(actual.target),"PROFILE_INSTALLATION_IDENTITY_CHANGED");
        if(ready)actual.activity.requireEligible(actual.target);
        last=actual;return actual.target;
    }
    ProfilePackages.Readback readback(){return last;}
    @Override public void guard()throws Exception{active.check();}
    @Override public long now(){return SystemClock.elapsedRealtime();}
    @Override public Object newCookie(){return new Binder();}
    @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
        return BackgroundTaskOrganizer.profileSnapshot(activityTasks);
    }
    @Override public ProfileTaskPolicy.Recents recents()throws Exception{
        return ProfileTaskPolicy.Recents.parse(BackgroundTaskOrganizer.profileRecents(deadline));
    }
    @Override public String publicRecentsDump()throws Exception{return BackgroundTaskOrganizer.profileRecents(deadline);}
    @Override public List<BackgroundOwnedSingleTask.Task> roots()throws Exception{return organizer.roots();}
    @Override public List<BackgroundOwnedSingleTask.Task> children(Object token)throws Exception{return organizer.children(token);}
    @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task root,
            BackgroundOwnedSingleTask.Task leaf)throws Exception{
        // No new process/service or task mutation. The existing binder dump is bounded by
        // its byte ceiling/deadline; real TaskInfo tokens/cookies bracket the full chain.
        // Retirement is permitted after cancellation. Do not reuse active-request
        // input guards here: this operation only gathers bounded identity evidence.
        long started=SystemClock.elapsedRealtime();
        ProfileTaskPolicy.need(started<deadline.getAsLong(),"PROFILE_PERMISSION_PROOF_DEADLINE");recheck(false);
        ProfilePermissionTransient.Authority before=packages.permissionController(expected.profile.userId,deadline.getAsLong());
        requireSamePermissionPair(root,leaf,"before_activity_dump");
        BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireOnlyOwned(expected,root.display,root.id,leaf.id);
        String chain=organizer.activitiesDump();
        ProfilePermissionTransient.Authority after=packages.permissionController(expected.profile.userId,deadline.getAsLong());
        ProfileTaskPolicy.need(before.same(after),"PROFILE_PERMISSION_SYSTEM_IDENTITY_CHANGED");
        requireSamePermissionPair(root,leaf,"after_activity_dump");recheck(false);
        BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireOnlyOwned(expected,root.display,root.id,leaf.id);
        ProfileTaskPolicy.need(SystemClock.elapsedRealtime()<deadline.getAsLong(),"PROFILE_PERMISSION_PROOF_DEADLINE");
        return ProfilePermissionTransient.verify(chain,expected,root,leaf,after,started,SystemClock.elapsedRealtime());
    }
    @Override public java.util.Map<String,Object> permissionReadMismatchEvidence(){return firstPermissionReadMismatch;}
    private synchronized void recordPermissionMismatch(String phase,List<BackgroundOwnedSingleTask.Task> roots,
            List<BackgroundOwnedSingleTask.Task> leaves,BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf){
        if(!firstPermissionReadMismatch.isEmpty())return;
        try{firstPermissionReadMismatch=ProfilePermissionTransient.readMismatch(phase,SystemClock.elapsedRealtime(),
                roots==null?-1:roots.size(),leaves==null?-1:leaves.size(),root,leaf,
                roots!=null&&roots.size()==1?roots.get(0):null,leaves!=null&&leaves.size()==1?leaves.get(0):null);}
        catch(RuntimeException ignored){/* Diagnostics cannot change the original refusal or create authority. */}
    }
    private void requireSamePermissionPair(BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,
            String phase)throws Exception{
        List<BackgroundOwnedSingleTask.Task> roots=organizer.roots();
        BackgroundOwnedSingleTask.Task currentRoot=roots!=null&&roots.size()==1?roots.get(0):null;
        boolean cookieExit=ProfilePermissionTransient.mayReadCookieExitLeaf(expected,root,currentRoot);
        if(!ProfilePermissionTransient.sameReadIdentity(root,currentRoot)&&!cookieExit){
            recordPermissionMismatch(phase,roots,null,root,leaf);
            throw new ProfileTaskPolicy.Refusal("PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ");
        }
        List<BackgroundOwnedSingleTask.Task> leaves=organizer.children(root.token);
        BackgroundOwnedSingleTask.Task currentLeaf=leaves!=null&&leaves.size()==1?leaves.get(0):null;
        if(!ProfilePermissionTransient.sameTaskInfo(root,currentRoot)||!ProfilePermissionTransient.sameTaskInfo(leaf,currentLeaf))
            recordPermissionMismatch(phase,roots,leaves,root,leaf);
        if(cookieExit)ProfilePermissionTransient.requireCookieExitRead(expected,root,leaf,currentRoot,currentLeaf);
        ProfilePermissionTransient.requireSameRead(expected,root,leaf,currentRoot,currentLeaf);
    }
    @Override public void createRoot(Object cookie)throws Exception{organizer.createRoot(cookie);}
    @Override public void bindRoot(Object token,Object cookie)throws Exception{organizer.bindProfileRoot(token,cookie);}
    @Override public void removeLeaf(Object token)throws Exception{organizer.removeOwnedLeaf(token);}
    @Override public boolean deleteRoot(Object token)throws Exception{return organizer.deleteOwnedContainer(token);}
    @Override public void removeLeaf(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{
        organizer.removeOwnedLeaf(token,()->check.check());
    }
    @Override public boolean deleteRoot(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{
        return organizer.deleteOwnedContainer(token,()->check.check());
    }
    @Override public void pause()throws Exception{Thread.sleep(20);}
}
