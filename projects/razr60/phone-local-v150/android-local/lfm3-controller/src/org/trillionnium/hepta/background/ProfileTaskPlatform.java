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
    ProfileTaskPlatform(Object activityTasks,ActivityOptions options,int display,ProfilePackages packages,
            ProfileTarget expected,BackgroundTaskOrganizer.Check active,LongSupplier deadline)throws Exception {
        this.activityTasks=activityTasks;this.packages=packages;this.expected=expected;
        this.active=active;this.deadline=deadline;
        organizer=new BackgroundTaskOrganizer(activityTasks,options,display,active,()->recheck(false),deadline);
    }
    static ProfilePackages.Readback preflight(Object activityTasks,ProfilePackages packages,
            ProfileTarget expected,long deadline)throws Exception {
        ProfilePackages.Readback actual=packages.read(expected.profile.userId,true,deadline);
        ProfileTaskPolicy.need(expected.same(actual.target),"PROFILE_INSTALLATION_IDENTITY_CHANGED");
        BackgroundTaskOrganizer.profileSnapshot(activityTasks).requireDedicatedEmpty(actual.target);
        ProfileTaskPolicy.Recents.parse(BackgroundTaskOrganizer.profileRecents(()->deadline))
                .requireDedicatedEmpty(actual.target);
        return actual;
    }
    @Override public ProfileTarget recheck(boolean ready)throws Exception {
        ProfilePackages.Readback actual=packages.read(expected.profile.userId,ready,deadline.getAsLong());
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
    @Override public List<BackgroundOwnedSingleTask.Task> roots()throws Exception{return organizer.roots();}
    @Override public List<BackgroundOwnedSingleTask.Task> children(Object token)throws Exception{return organizer.children(token);}
    @Override public void createRoot(Object cookie)throws Exception{organizer.createRoot(cookie);}
    @Override public void bindRoot(Object token,Object cookie)throws Exception{organizer.bindProfileRoot(token,cookie);}
    @Override public void removeLeaf(Object token)throws Exception{organizer.removeOwnedLeaf(token);}
    @Override public boolean deleteRoot(Object token)throws Exception{return organizer.deleteOwnedContainer(token);}
    @Override public void pause()throws Exception{Thread.sleep(20);}
}
