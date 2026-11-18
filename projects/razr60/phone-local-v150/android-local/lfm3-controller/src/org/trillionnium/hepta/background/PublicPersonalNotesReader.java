package org.trillionnium.hepta.background;

import android.app.ActivityOptions;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.SystemClock;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
    private final String sourceDir;
    PublicPersonalNotesReader(Context context,Object activities,int display,LongSupplier deadline)throws Exception{
        this.context=context;this.activities=activities;this.deadline=deadline;
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
        List<PublicPersonalNotesCustody.Node> nodes=new ArrayList<PublicPersonalNotesCustody.Node>();Set<Integer> ids=new HashSet<Integer>();
        for(BackgroundOwnedSingleTask.Task root:reader.roots())nodes.add(node(root,ids,0));
        ProfileTaskPolicy.Snapshot global=BackgroundTaskOrganizer.profileSnapshot(activities);check();
        return new PublicPersonalNotesCustody.Frame(global,nodes,begin,SystemClock.elapsedRealtime());
    }
    private PublicPersonalNotesCustody.Node node(BackgroundOwnedSingleTask.Task task,Set<Integer> ids,int depth)throws Exception{
        need(task!=null&&depth<=4&&ids.size()<PublicPersonalNotesCustody.MAX_TASKS&&ids.add(task.id),"NOTES_TASK_TREE_INVALID");
        List<PublicPersonalNotesCustody.Node> children=new ArrayList<PublicPersonalNotesCustody.Node>();
        for(BackgroundOwnedSingleTask.Task child:reader.children(task.token))children.add(node(child,ids,depth+1));
        return new PublicPersonalNotesCustody.Node(task,children);
    }
    ProfileTaskPolicy.Snapshot global()throws Exception{check();ProfileTaskPolicy.Snapshot value=BackgroundTaskOrganizer.profileSnapshot(activities);check();return value;}
    PublicOwnGroupPhysicalFence.RecentCensus recents()throws Exception{
        check();PublicOwnGroupPhysicalFence.RecentCensus value=PublicOwnGroupPhysicalFence.inspectRecents(BackgroundTaskOrganizer.profileRecents(deadline));check();return value;
    }
}
