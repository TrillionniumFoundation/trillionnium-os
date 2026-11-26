package org.trillionnium.hepta.background;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.hardware.display.DisplayManager;
import android.os.IBinder;
import android.os.SystemClock;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;

/** Actual Android-16 TaskInfo/WCT boundary. Only an original custodian's private
 * Effect enters removeTask(WindowContainerToken). No ID, launch, reparent,
 * organizer-root removal, process signal, or business RPC entry exists. */
final class PublicPersonalNotesRetirementAdapter implements PublicPersonalNotesRetirement.Port {
    interface Check {void check() throws Exception;}
    private final Context context;
    private final Object activities,windows,windowOrganizer,taskOrganizer;
    private final DisplayManager displays;
    private final PublicPersonalNotesReader reader;
    private final PublicOwnGroupFramework framework;
    private final Check originalHandle;
    private final int display,uid;
    private final String name,sourceDir;
    private final long deadline;
    private final Method allRoots,runningTasks,childTasks,tokenBinder,apply,remove,rootProjection;
    private final Class<?> transactionType,tokenType;
    private final Map<Object,Object> wrappers=new LinkedHashMap<Object,Object>();
    private boolean releasedRead;

    PublicPersonalNotesRetirementAdapter(Context context,Object activities,Object windows,DisplayManager displays,
            PublicPersonalNotesReader reader,PublicOwnGroupFramework framework,int display,String name,int uid,
            long deadline,Check originalHandle) throws Exception {
        need(android.os.Build.VERSION.SDK_INT==36&&android.os.Process.myUid()==0&&context!=null&&activities!=null
                &&windows!=null&&displays!=null&&reader!=null&&framework!=null&&display>1&&name!=null&&originalHandle!=null,
                "NOTES_RETIREMENT_PLATFORM_OR_BINDING");
        this.context=context;this.activities=activities;this.windows=windows;this.displays=displays;this.reader=reader;
        this.framework=framework;this.display=display;this.name=name;this.uid=uid;this.deadline=deadline;this.originalHandle=originalHandle;
        ApplicationInfo info=context.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
        need(info!=null&&info.uid==uid&&info.enabled&&info.sourceDir!=null&&info.sourceDir.startsWith("/"),"NOTES_RETIREMENT_INSTALLATION");sourceDir=info.sourceDir;
        Class<?> atm=Class.forName("android.app.IActivityTaskManager");allRoots=atm.getMethod("getAllRootTaskInfos");
        runningTasks=atm.getMethod("getTasks",int.class,boolean.class,boolean.class,int.class);
        tokenType=Class.forName("android.window.WindowContainerToken");tokenBinder=tokenType.getMethod("asBinder");
        transactionType=Class.forName("android.window.WindowContainerTransaction");
        windowOrganizer=atm.getMethod("getWindowOrganizerController").invoke(activities);
        need(windowOrganizer!=null,"NOTES_RETIREMENT_WCT_UNAVAILABLE");
        Class<?> woc=Class.forName("android.window.IWindowOrganizerController");
        apply=woc.getMethod("applyTransaction",transactionType);
        taskOrganizer=woc.getMethod("getTaskOrganizerController").invoke(windowOrganizer);
        need(taskOrganizer!=null,"NOTES_RETIREMENT_TASK_READER_UNAVAILABLE");
        childTasks=Class.forName("android.window.ITaskOrganizerController").getMethod("getChildTasks",tokenType,int[].class);
        remove=transactionType.getMethod("removeTask",tokenType);
        // Read-only reuse of the unchanged complete child-array parser, including
        // its strict bounds and malformed/partial response refusal.
        rootProjection=BackgroundTaskOrganizer.class.getDeclaredMethod("profileSnapshotRows",Object.class);rootProjection.setAccessible(true);
        guard(false);
    }
    @Override public long now(){return SystemClock.elapsedRealtime();}
    @Override public void awaitRead()throws Exception{time();Thread.sleep(1);time();}
    private void time()throws IOException{need(now()<deadline,"NOTES_RETIREMENT_ORIGINAL_DEADLINE");}
    private void guard(boolean afterRelease)throws Exception{
        time();originalHandle.check();
        ApplicationInfo info=context.getPackageManager().getApplicationInfo(PublicPersonalNotesCustody.PACKAGE,0);
        need(info!=null&&info.uid==uid&&info.enabled&&sourceDir.equals(info.sourceDir),"NOTES_RETIREMENT_INSTALLATION_CHANGED");
        String[] owners=context.getPackageManager().getPackagesForUid(uid);
        need(owners!=null&&owners.length==1&&PublicPersonalNotesCustody.PACKAGE.equals(owners[0]),
                "NOTES_RETIREMENT_SHARED_UID_FORBIDDEN");
        if(!afterRelease)framework.requireRetiredDestroyHandle(display,name);
        time();
    }
    @Override public PublicPersonalNotesRetirement.Sample read()throws Exception{
        need(!releasedRead,"NOTES_RETIREMENT_ACTION_AFTER_RELEASE");return read(null);
    }
    @Override public PublicPersonalNotesRetirement.Sample readAfter(PublicPersonalNotesRetirement.Effect effect)throws Exception{
        need(effect!=null&&!releasedRead,"NOTES_RETIREMENT_RETURNED_EFFECT_REQUIRED");
        return readPending(effect.pendingRead());
    }
    private PublicPersonalNotesRetirement.Sample readPending(PublicPersonalNotesRetirement.PendingRead pending)throws Exception{
        for(int attempt=1;attempt<=3;attempt++){
            long begin=now();guard(false);
            PublicPersonalNotesReader.RetirementFrames before=reader.frameDuringRetirement(pending);
            PublicPersonalNotesCustody.Frame first=before.last();
            ActualRead actual=actualTasks(first.global,pending);
            Physical physical=physical();
            PublicPersonalNotesReader.RetirementFrames after=reader.frameDuringRetirement(pending);
            PublicPersonalNotesCustody.Frame ending=after.last();
            guard(false);long end=now();
            List<PublicPersonalNotesCustody.Frame> frames=new ArrayList<PublicPersonalNotesCustody.Frame>(before.frames);frames.addAll(after.frames);
            boolean settle=pending.facts(frames,physical.recents,physical.hashes,begin,end);
            String mismatch=actual.changed?"NOTES_RETIREMENT_ACTUAL_GLOBAL_CHANGED":null;
            if(!before.stable||!after.stable)mismatch="NOTES_RETIREMENT_FRAME_CHANGED_DURING_READ";
            if(!PublicPersonalNotesRetirement.protectedGlobal(first.global).equals(PublicPersonalNotesRetirement.protectedGlobal(ending.global)))mismatch="NOTES_RETIREMENT_GLOBAL_CHANGED_DURING_READ";
            else if(first.roots.size()!=ending.roots.size())mismatch="NOTES_RETIREMENT_ROOTS_CHANGED_DURING_READ";
            else for(int i=0;i<ending.roots.size();i++){
                PublicPersonalNotesCustody.Node root=ending.roots.get(i),old=first.roots.get(i);
                if(!(old.children.isEmpty()&&root.children.isEmpty()&&PublicPersonalNotesRetirement.sameTask(old.task,root.task)
                        &&PublicPersonalNotesRetirement.sameTask(root.task,actual.tasks.get(root.task.id))))
                    mismatch="NOTES_RETIREMENT_FINAL_TASKINFO_CHANGED";
            }
            if(settle&&mismatch==null)mismatch="NOTES_RETIREMENT_PENDING_DETACHED_RECENT";
            if(mismatch==null)return new PublicPersonalNotesRetirement.Sample(ending,physical.recents,actual.tasks,physical.hashes,begin,end,display,uid);
            if(attempt==3)throw pending.refusal(mismatch,"complete_post_returned_read_bound",first.global,ending.global,actual.tasks);
            awaitRead();
        }
        throw new IOException("NOTES_RETIREMENT_PENDING_READ_BOUND");
    }
    PublicPersonalNotesRetirement.Sample readReleased(PublicPersonalNotesCustody.ReleasedRead authority)throws Exception{
        need(authority!=null,"NOTES_RETIREMENT_RELEASED_READ_REQUIRED");releasedRead=true;return read(authority);
    }
    private PublicPersonalNotesRetirement.Sample read(PublicPersonalNotesCustody.ReleasedRead authority)throws Exception{
        long begin=now();boolean after=authority!=null;guard(after);
        PublicPersonalNotesCustody.Frame first=after?reader.frameAfterRelease(authority):reader.frame();
        Map<Integer,BackgroundOwnedSingleTask.Task> actual=actualTasks(first.global);
        Physical physical=physical();
        PublicPersonalNotesCustody.Frame ending=after?reader.frameAfterRelease(authority):reader.frame();
        need(PublicPersonalNotesRetirement.protectedGlobal(first.global).equals(PublicPersonalNotesRetirement.protectedGlobal(ending.global)),"NOTES_RETIREMENT_GLOBAL_CHANGED_DURING_READ");
        need(first.roots.size()==ending.roots.size(),"NOTES_RETIREMENT_ROOTS_CHANGED_DURING_READ");
        for(int i=0;i<ending.roots.size();i++){
            PublicPersonalNotesCustody.Node root=ending.roots.get(i),old=first.roots.get(i);
            need(old.children.isEmpty()&&root.children.isEmpty()&&PublicPersonalNotesRetirement.sameTask(old.task,root.task)
                    &&PublicPersonalNotesRetirement.sameTask(root.task,actual.get(root.task.id)),"NOTES_RETIREMENT_FINAL_TASKINFO_CHANGED");
        }
        guard(after);long end=now();need(end-begin<=1500,"NOTES_RETIREMENT_SAMPLE_AGE");
        return new PublicPersonalNotesRetirement.Sample(ending,physical.recents,actual,physical.hashes,begin,end,display,uid);
    }
    private static final class ActualRead{
        final Map<Integer,BackgroundOwnedSingleTask.Task> tasks;final boolean changed;
        ActualRead(Map<Integer,BackgroundOwnedSingleTask.Task> tasks,boolean changed){this.tasks=tasks;this.changed=changed;}
    }
    private Map<Integer,BackgroundOwnedSingleTask.Task> actualTasks(ProfileTaskPolicy.Snapshot expected)throws Exception{
        return actualTasks(expected,null).tasks;
    }
    private ActualRead actualTasks(ProfileTaskPolicy.Snapshot expected,PublicPersonalNotesRetirement.PendingRead pending)throws Exception{
        time();Object raw=allRoots.invoke(activities);time();
        ProfileTaskPolicy.Snapshot global=(ProfileTaskPolicy.Snapshot)rootProjection.invoke(null,raw);
        boolean changed=!PublicPersonalNotesRetirement.protectedGlobal(global).equals(PublicPersonalNotesRetirement.protectedGlobal(expected));
        if(pending==null)need(!changed,"NOTES_RETIREMENT_ACTUAL_GLOBAL_CHANGED");
        need(raw instanceof List&&((List<?>)raw).size()<=ProfileTaskPolicy.MAX_ROOTS,"NOTES_RETIREMENT_ROOT_QUERY");
        Map<Integer,BackgroundOwnedSingleTask.Task> out=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
        wrappers.clear();for(Object row:(List<?>)raw)put(out,row,false);
        // RunningTasks alone deliberately omits finishing/empty tasks in AOSP.
        // Root TaskInfos fill ordinary empty root-as-leaf rows. For missing
        // nested leaves, read only the actual organizer-created parent tokens;
        // a null/unsupported/incomplete response never supplies a guessed UID.
        Object leaves=runningTasks.invoke(activities,ProfileTaskPolicy.MAX_LEAVES+1,false,true,-1);time();
        need(leaves instanceof List&&((List<?>)leaves).size()<=ProfileTaskPolicy.MAX_LEAVES,"NOTES_RETIREMENT_LEAF_QUERY_BOUND");
        Set<Integer> unique=new LinkedHashSet<Integer>();
        for(Object row:(List<?>)leaves){int id=integer(row,"taskId");need(unique.add(id),"NOTES_RETIREMENT_LEAF_DUPLICATE");changed|=put(out,row,true,pending);}
        for(ProfileTaskPolicy.Root root:global.roots){
            Set<Integer> expectedLeaves=new LinkedHashSet<Integer>();boolean missing=false;
            for(ProfileTaskPolicy.Leaf leaf:global.leaves.values())if(leaf.parent==root.id){
                expectedLeaves.add(leaf.id);BackgroundOwnedSingleTask.Task node=out.get(leaf.id);Set<Integer> chain=new LinkedHashSet<Integer>();
                if(PublicPersonalNotesRetirement.ordinaryForeignRootMember(global,out,leaf,display,uid))continue;
                while(node!=null&&node.id!=root.id){
                    need(chain.size()<8&&chain.add(node.id)&&node.parent>0,"NOTES_RETIREMENT_RUNNING_ANCESTRY_INVALID");
                    node=out.get(node.parent);
                }
                missing|=node==null;
            }
            if(missing){Set<Integer> found=new LinkedHashSet<Integer>(),visited=new LinkedHashSet<Integer>();
                readChildren(out.get(root.id),out,expectedLeaves,found,visited,0);
                need(found.equals(expectedLeaves),"NOTES_RETIREMENT_CHILD_CENSUS_INCOMPLETE");
            }
        }
        need(out.keySet().containsAll(global.allIds),"NOTES_RETIREMENT_ACTUAL_UID_CENSUS_INCOMPLETE");
        if(pending!=null)pending.actual(global,out);return new ActualRead(out,changed);
    }
    private void readChildren(BackgroundOwnedSingleTask.Task parent,Map<Integer,BackgroundOwnedSingleTask.Task> out,
            Set<Integer> expectedLeaves,Set<Integer> found,Set<Integer> visited,int depth)throws Exception{
        time();need(parent!=null&&depth<8&&visited.add(parent.id)&&visited.size()<=ProfileTaskPolicy.MAX_LEAVES,
                "NOTES_RETIREMENT_CHILD_READ_BOUND");
        Object wrapper=wrappers.get(parent.token);need(tokenType.isInstance(wrapper),"NOTES_RETIREMENT_CHILD_PARENT_TOKEN");
        Object raw=childTasks.invoke(taskOrganizer,wrapper,null);time();
        need(raw instanceof List&&((List<?>)raw).size()>0&&((List<?>)raw).size()<=ProfileTaskPolicy.MAX_LEAVES,
                "NOTES_RETIREMENT_CHILD_QUERY_UNAVAILABLE");
        Set<Integer> siblings=new LinkedHashSet<Integer>();
        for(Object value:(List<?>)raw){
            int id=integer(value,"taskId");need(siblings.add(id)&&id!=parent.id,"NOTES_RETIREMENT_CHILD_DUPLICATE_OR_CYCLE");
            put(out,value,true);BackgroundOwnedSingleTask.Task child=out.get(id);
            need(child.parent==parent.id&&child.display==parent.display&&out.size()<=ProfileTaskPolicy.MAX_LEAVES+ProfileTaskPolicy.MAX_ROOTS,
                    "NOTES_RETIREMENT_CHILD_PARENT_CHANGED");
            if(expectedLeaves.contains(id))need(found.add(id),"NOTES_RETIREMENT_LEAF_DUPLICATE");
            else readChildren(child,out,expectedLeaves,found,visited,depth+1);
        }
    }
    private void put(Map<Integer,BackgroundOwnedSingleTask.Task> out,Object row,boolean duplicateRootAllowed)throws Exception{
        put(out,row,duplicateRootAllowed,null);
    }
    private boolean put(Map<Integer,BackgroundOwnedSingleTask.Task> out,Object row,boolean duplicateRootAllowed,
            PublicPersonalNotesRetirement.PendingRead pending)throws Exception{
        need(row!=null,"NOTES_RETIREMENT_NULL_TASKINFO");Object wrapper=field(row,"token");
        need(tokenType.isInstance(wrapper),"NOTES_RETIREMENT_TOKEN_WRAPPER_UNKNOWN");Object binder=tokenBinder.invoke(wrapper);
        need(binder instanceof IBinder,"NOTES_RETIREMENT_BINDER_UNKNOWN");
        Object rawCookies=field(row,"launchCookies");need(rawCookies instanceof List&&((List<?>)rawCookies).size()<=128,"NOTES_RETIREMENT_COOKIES");
        List<Object> cookies=new ArrayList<Object>();for(Object cookie:(List<?>)rawCookies){need(cookie instanceof IBinder,"NOTES_RETIREMENT_COOKIE");cookies.add(cookie);}
        Object intent=field(row,"baseIntent");need(intent instanceof Intent,"NOTES_RETIREMENT_BASE_INTENT");
        String top=component(field(row,"topActivity"));Object rawInfo=field(row,"topActivityInfo");int topUid=-1;
        if(rawInfo!=null){need(rawInfo instanceof ActivityInfo,"NOTES_RETIREMENT_TOP_INFO");ActivityInfo info=(ActivityInfo)rawInfo;
            // RootTaskInfo exposes the original Intent component; RunningTaskInfo
            // exposes ActivityRecord's resolved component. An actual ActivityInfo
            // alias binds both names to the same package and application UID.
            need(info.applicationInfo!=null&&info.packageName!=null&&info.name!=null&&info.packageName.equals(info.applicationInfo.packageName)
                    &&((info.packageName+"/"+info.name).equals(top)
                        ||(info.targetActivity!=null&&!info.targetActivity.isEmpty()
                            &&(info.packageName+"/"+info.targetActivity).equals(top))),
                    "NOTES_RETIREMENT_TOP_IDENTITY");topUid=info.applicationInfo.uid;
        }else need(top==null,"NOTES_RETIREMENT_TOP_UID_MISSING");
        BackgroundOwnedSingleTask.Task task=new BackgroundOwnedSingleTask.Task(integer(row,"taskId"),integer(row,"displayId"),integer(row,"userId"),
                integer(row,"parentTaskId"),integer(row,"effectiveUid"),topUid,integer(row,"numActivities"),binder,cookies,
                component(((Intent)intent).getComponent()),component(field(row,"baseActivity")),top,component(field(row,"realActivity")),
                component(field(row,"origActivity")),bool(row,"isRunning"),bool(row,"isVisible"));
        BackgroundOwnedSingleTask.Task old=out.put(task.id,task);
        boolean changed=old!=null&&!PublicPersonalNotesRetirement.sameTask(old,task);
        if(changed&&duplicateRootAllowed&&PublicPersonalNotesRetirement.sameUnrelatedPhysicalIdentity(old,task,uid))changed=false;
        else if(changed&&duplicateRootAllowed&&pending!=null)pending.pair(old,task);
        else need(old==null||(duplicateRootAllowed&&!changed),"NOTES_RETIREMENT_DUPLICATE_TASKINFO_CHANGED");
        Object prior=wrappers.put(binder,wrapper);need(prior==null||binder.equals(tokenBinder.invoke(prior)),"NOTES_RETIREMENT_WRAPPER_CHANGED");
        return changed;
    }
    @Override public void remove(PublicPersonalNotesRetirement.Effect effect)throws Exception{
        need(effect!=null&&!releasedRead,"NOTES_RETIREMENT_PRIVATE_EFFECT_REQUIRED");
        PublicPersonalNotesRetirement.Sample finalRead=effect.finalRead(this);
        if(effect.skipAbsent(finalRead,now()))return;
        Object wrapper=wrappers.get(effect.token());need(tokenType.isInstance(wrapper)&&effect.token().equals(tokenBinder.invoke(wrapper)),"NOTES_RETIREMENT_ORIGINAL_BINDER_NOT_FRESH");
        BackgroundOwnedSingleTask.Task row=finalRead.actualTasks.get(effect.id());
        need(row!=null&&Objects.equals(row.token,effect.token()),"NOTES_RETIREMENT_FINAL_WRAPPER_SUBSTITUTED");
        Object transaction=transactionType.getConstructor().newInstance();remove.invoke(transaction,wrapper);
        guard(false);effect.beforeCall(finalRead,now());
        // AOSP REMOVE_TASK uses killProcess=true for a leaf and removes recents.
        // This is why the complete foreign same-UID census is mandatory.
        apply.invoke(windowOrganizer,transaction);effect.returned();time();
    }
    private static final class Physical {
        final String recents;final Map<Integer,String> hashes;
        Physical(String recents,Map<Integer,String> hashes){this.recents=recents;this.hashes=hashes;}
    }
    @SuppressWarnings("unchecked")
    private Physical physical()throws Exception{
        LongSupplier limit=()->deadline;
        Method factsMethod=PublicOwnGroupPhysicalReader.class.getDeclaredMethod("displayFacts",DisplayManager.class);factsMethod.setAccessible(true);
        Method dump=PublicOwnGroupPhysicalReader.class.getDeclaredMethod("dump",Object.class,String[].class,LongSupplier.class);dump.setAccessible(true);
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> before=(Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts>)factsMethod.invoke(null,displays);
        Object am=Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
        String recents=(String)dump.invoke(null,am,new String[]{"-a","recents"},limit);
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> after=(Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts>)factsMethod.invoke(null,displays);
        Map<Integer,String> result=new LinkedHashMap<Integer,String>();
        // This port has no input or focus effect. Keep physical display identity
        // separate from the user's independently changing foreground task/IME.
        for(int id:new int[]{0,1}){
            need(before.get(id)!=null&&after.get(id)!=null&&before.get(id).data().equals(after.get(id).data()),
                    "NOTES_RETIREMENT_PHYSICAL_CHANGED_DURING_READ");
            result.put(id,ProfileIdentity.sha(("hepta.notes-retirement.physical-identity.v2|"+after.get(id).data()).getBytes(StandardCharsets.UTF_8)));
        }
        time();return new Physical(recents,Collections.unmodifiableMap(result));
    }
    static boolean displayAbsent(int display,String name)throws Exception{
        need(display>1&&name!=null,"NOTES_RETIREMENT_DISPLAY_BINDING");
        Object binder=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"display");
        need(binder instanceof IBinder,"NOTES_RETIREMENT_DISPLAY_SERVICE");
        Object service=Class.forName("android.hardware.display.IDisplayManager$Stub").getMethod("asInterface",IBinder.class).invoke(null,binder);
        Class<?> api=Class.forName("android.hardware.display.IDisplayManager"),type=Class.forName("android.view.DisplayInfo");
        Method ids=api.getMethod("getDisplayIds",boolean.class),info=api.getMethod("getDisplayInfo",int.class);
        Object raw=ids.invoke(service,true);need(raw instanceof int[]&&((int[])raw).length>=2&&((int[])raw).length<=32,"NOTES_RETIREMENT_DISABLED_DISPLAY_CENSUS");
        Set<Integer> seen=new LinkedHashSet<Integer>();boolean present=false;
        for(int id:(int[])raw){Object row=info.invoke(service,id);need(id>=0&&seen.add(id)&&type.isInstance(row)&&integer(row,"displayId")==id,"NOTES_RETIREMENT_DISPLAY_ROW");
            Object actualName=field(row,"name");need(actualName instanceof String,"NOTES_RETIREMENT_DISPLAY_NAME");
            if(id==display||name.equals(actualName))present=true;
        }
        Object end=ids.invoke(service,true);need(end instanceof int[]&&java.util.Arrays.equals((int[])raw,(int[])end)&&seen.contains(0)&&seen.contains(1),"NOTES_RETIREMENT_DISPLAY_CENSUS_CHANGED");
        need(present||info.invoke(service,display)==null,"NOTES_RETIREMENT_DIRECT_DISPLAY_DISAGREES");return !present;
    }
    private static Object field(Object row,String name)throws Exception{return row.getClass().getField(name).get(row);}
    private static int integer(Object row,String name)throws Exception{Object value=field(row,name);need(value instanceof Integer,"NOTES_RETIREMENT_INTEGER");return (Integer)value;}
    private static boolean bool(Object row,String name)throws Exception{Object value=field(row,name);need(value instanceof Boolean,"NOTES_RETIREMENT_BOOLEAN");return (Boolean)value;}
    private static String component(Object value)throws IOException{if(value==null)return null;need(value instanceof ComponentName,"NOTES_RETIREMENT_COMPONENT");
        ComponentName component=(ComponentName)value;return component.getPackageName()+"/"+component.getClassName();}
    private static void append(StringBuilder out,String value){out.append(value.length()).append(':').append(value);}
    private static void need(boolean value,String reason)throws IOException{if(!value)throw new IOException(reason);}
}
