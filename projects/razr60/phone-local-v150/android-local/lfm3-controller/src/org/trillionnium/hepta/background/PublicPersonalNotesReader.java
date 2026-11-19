package org.trillionnium.hepta.background;

import android.app.ActivityOptions;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.SystemClock;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;

/** Actual read-only TaskInfo/UID/token and complete recents adapter.
 * It never calls the organizer's create/reparent/remove/bind methods. Both
 * organizer mutation guards are unconditionally throwing boundaries. */
final class PublicPersonalNotesReader {
    private final Context context;
    private final Object activities;
    private final BackgroundTaskOrganizer reader;
    private final LongSupplier deadline;
    final int uid;
    private final int display;
    private final String sourceDir;
    PublicPersonalNotesReader(Context context,Object activities,int display,LongSupplier deadline)throws Exception{
        this.context=context;this.activities=activities;this.deadline=deadline;
        need(display>1,"NOTES_OWN_DISPLAY_INVALID");this.display=display;
        ApplicationInfo installed=context.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
        need(installed!=null&&installed.uid>=10000&&installed.uid<90000&&installed.enabled
                &&installed.sourceDir!=null&&installed.sourceDir.startsWith("/"),"NOTES_INSTALLATION_UNAVAILABLE");
        uid=installed.uid;sourceDir=installed.sourceDir;
        BackgroundTaskOrganizer.Check forbid=()->{throw new IOException("NOTES_READ_ADAPTER_MUTATION_FORBIDDEN");};
        reader=new BackgroundTaskOrganizer(activities,ActivityOptions.makeBasic().setLaunchDisplayId(display),display,forbid,forbid,deadline);
    }
    private static void need(boolean yes,String reason)throws IOException{if(!yes)throw new IOException(reason);}
    private void check()throws Exception{
        need(SystemClock.elapsedRealtime()<deadline.getAsLong(),"NOTES_TASK_READ_DEADLINE");
        ApplicationInfo current=context.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
        need(current!=null&&current.uid==uid&&current.enabled&&sourceDir.equals(current.sourceDir),"NOTES_INSTALLATION_CHANGED");
    }
    synchronized PublicPersonalNotesCustody.Frame frame()throws Exception{
        long begin=SystemClock.elapsedRealtime();check();
        // Ordinary Intent-created Notes roots are not organizer-created containers.
        // Android 16 getChildTasks() returns null for such tasks; null is not an
        // empty-child proof. Use two complete independent ATM leaf censuses around
        // the real organizer root TaskInfo query, without ever calling children().
        BackgroundTaskOrganizer.ReadOnlyRootCensus before=reader.readOnlyRootCensus();
        List<BackgroundOwnedSingleTask.Task> actual=reader.roots();
        BackgroundTaskOrganizer.ReadOnlyRootCensus after=reader.readOnlyRootCensus();
        Map<Integer,BackgroundOwnedSingleTask.Task> first=index(before.displayRoots);
        Map<Integer,BackgroundOwnedSingleTask.Task> middle=index(actual),last=index(after.displayRoots);
        need(first.keySet().equals(middle.keySet())&&middle.keySet().equals(last.keySet()),"NOTES_ROOT_CENSUS_CHANGED");
        List<PublicPersonalNotesCustody.Node> nodes=new ArrayList<PublicPersonalNotesCustody.Node>();
        for(BackgroundOwnedSingleTask.Task task:actual){
            sameActualTask(first.get(task.id),task);sameActualTask(task,last.get(task.id));
            requireSoleLeaf(before.global,task);requireSoleLeaf(after.global,task);
            nodes.add(new PublicPersonalNotesCustody.Node(task,Collections.<PublicPersonalNotesCustody.Node>emptyList()));
        }
        check();
        return new PublicPersonalNotesCustody.Frame(after.global,nodes,begin,SystemClock.elapsedRealtime());
    }
    private Map<Integer,BackgroundOwnedSingleTask.Task> index(List<BackgroundOwnedSingleTask.Task> tasks)throws Exception{
        need(tasks!=null&&tasks.size()<=PublicPersonalNotesCustody.MAX_TASKS,"NOTES_ROOT_CENSUS_UNAVAILABLE");
        Map<Integer,BackgroundOwnedSingleTask.Task> out=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
        for(BackgroundOwnedSingleTask.Task task:tasks){
            need(task!=null&&task.id>0&&task.display==display&&task.user==0&&task.parent<0
                    &&task.token!=null&&out.put(task.id,task)==null,"NOTES_ROOT_IDENTITY_UNAVAILABLE");
            need(task.uid==uid&&(task.topUid==uid||(task.activities==0&&task.topUid==-1))
                    &&inPackage(task.intentComponent)&&inPackage(task.base)&&inPackage(task.real)
                    &&nullablePackage(task.top)&&nullablePackage(task.orig),"NOTES_ROOT_UID_OR_COMPONENT_UNAVAILABLE");
        }
        return out;
    }
    private static boolean inPackage(String value){
        return value!=null&&value.startsWith(PublicPersonalNotesCustody.PACKAGE+"/");
    }
    private static boolean nullablePackage(String value){return value==null||inPackage(value);}
    private static void sameActualTask(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b)throws Exception{
        need(a!=null&&b!=null&&a.id==b.id&&a.display==b.display&&a.user==b.user&&a.parent==b.parent
                &&a.uid==b.uid&&a.topUid==b.topUid&&a.activities==b.activities&&a.running==b.running
                &&a.visible==b.visible&&Objects.equals(a.token,b.token)&&a.cookies.equals(b.cookies)
                &&Objects.equals(a.intentComponent,b.intentComponent)&&Objects.equals(a.base,b.base)
                &&Objects.equals(a.top,b.top)&&Objects.equals(a.real,b.real)&&Objects.equals(a.orig,b.orig),
                "NOTES_ROOT_TASKINFO_CHANGED");
    }
    private void requireSoleLeaf(ProfileTaskPolicy.Snapshot global,BackgroundOwnedSingleTask.Task task)throws Exception{
        need(global!=null,"NOTES_GLOBAL_CENSUS_UNAVAILABLE");
        ProfileTaskPolicy.Root actualRoot=null;
        for(ProfileTaskPolicy.Root root:global.roots)if(root.id==task.id){
            need(actualRoot==null,"NOTES_GLOBAL_ROOT_DUPLICATE");actualRoot=root;
        }
        need(actualRoot!=null&&actualRoot.display==display&&actualRoot.user==0
                &&actualRoot.activities==task.activities&&Objects.equals(actualRoot.base,task.base)
                &&Objects.equals(actualRoot.top,task.top),"NOTES_GLOBAL_ROOT_DISAGREES");
        // RootTaskInfo.visible is shouldBeVisible(), whereas TaskInfo.isVisible is
        // a different actual framework field. Never equate or synthesize them.
        int leaves=0;
        for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(leaf.parent==task.id){
            leaves++;
            String expected=task.orig!=null?task.orig:task.real;
            need(leaf.id==task.id&&leaf.display==display&&leaf.user==0
                    &&expected!=null&&expected.equals(leaf.name),"NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF");
        }
        need(leaves==1,"NOTES_ROOT_IS_NOT_PROVEN_SOLE_LEAF");
    }
    ProfileTaskPolicy.Snapshot global()throws Exception{check();ProfileTaskPolicy.Snapshot value=BackgroundTaskOrganizer.profileSnapshot(activities);check();return value;}
    PublicOwnGroupPhysicalFence.RecentCensus recents()throws Exception{
        check();PublicOwnGroupPhysicalFence.RecentCensus value=PublicOwnGroupPhysicalFence.inspectRecents(BackgroundTaskOrganizer.profileRecents(deadline));check();return value;
    }
}
