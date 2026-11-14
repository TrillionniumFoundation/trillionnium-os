package org.trillionnium.hepta.background;

import android.app.ActivityOptions;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/** Exact hidden framework capability; it never registers a global TaskOrganizer or invokes adb. */
final class BackgroundTaskOrganizer implements BackgroundOwnedSingleTask.Platform {
    interface Check { void check() throws Exception; }
    private final Object activityTasks, organizer, windowOrganizer;
    private final Method roots, children, create, delete, allRoots, apply;
    private final Method reparent, remove, tokenBinder, setTask, setRoot, setCookie;
    private final Class<?> transactionType;
    private final ActivityOptions options;
    private final int display, fullscreen;
    private final Check activeCheck, locationCheck;
    private final LongSupplier deadline;
    private final IBinder activityManager;
    private final Map<Object,Object> tokenWrappers=new HashMap<Object,Object>();

    BackgroundTaskOrganizer(Object activityTasks, ActivityOptions options, int display,
                            Check activeCheck, Check locationCheck, LongSupplier deadline) throws Exception {
        this.activityTasks=activityTasks;this.options=options;this.display=display;
        this.activeCheck=activeCheck;this.locationCheck=locationCheck;this.deadline=deadline;
        if(android.os.Build.VERSION.SDK_INT!=36)throw new IOException("OWNED_TASK_PLATFORM_VERSION_UNSUPPORTED");
        Class<?> atm=Class.forName("android.app.IActivityTaskManager");
        Class<?> woc=Class.forName("android.window.IWindowOrganizerController");
        Class<?> toc=Class.forName("android.window.ITaskOrganizerController");
        Class<?> token=Class.forName("android.window.WindowContainerToken");
        transactionType=Class.forName("android.window.WindowContainerTransaction");
        windowOrganizer=atm.getMethod("getWindowOrganizerController").invoke(activityTasks);
        organizer=woc.getMethod("getTaskOrganizerController").invoke(windowOrganizer);
        roots=toc.getMethod("getRootTasks",int.class,int[].class);
        children=toc.getMethod("getChildTasks",token,int[].class);
        create=toc.getMethod("createRootTask",int.class,int.class,IBinder.class,boolean.class);
        delete=toc.getMethod("deleteRootTask",token);
        allRoots=atm.getMethod("getAllRootTaskInfos");
        apply=woc.getMethod("applyTransaction",transactionType);
        reparent=transactionType.getMethod("reparent",token,token,boolean.class);
        remove=transactionType.getMethod("removeTask",token);
        tokenBinder=token.getMethod("asBinder");
        setTask=ActivityOptions.class.getMethod("setLaunchTaskId",int.class);
        setRoot=ActivityOptions.class.getMethod("setLaunchRootTask",token);
        setCookie=ActivityOptions.class.getMethod("setLaunchCookie",IBinder.class);
        fullscreen=Class.forName("android.app.WindowConfiguration").getField("WINDOWING_MODE_FULLSCREEN").getInt(null);
        if(fullscreen!=1||display<=0||organizer==null||windowOrganizer==null)throw new IOException("OWNED_TASK_FRAMEWORK_UNAVAILABLE");
        Object am=Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
        if(!(am instanceof IInterface))throw new IOException("OWNED_TASK_DUMP_SERVICE_UNAVAILABLE");
        activityManager=((IInterface)am).asBinder();
        if(activityManager==null)throw new IOException("OWNED_TASK_DUMP_SERVICE_UNAVAILABLE");
    }

    /** This registered empty home entry avoids the launcher's singleTask trampoline. No query is supplied. */
    static Intent nativeHome(Context context, Intent launcher) throws Exception {
        ComponentName source=launcher==null?null:launcher.getComponent();
        if(source==null||!BackgroundOwnedSingleTask.PACKAGE.equals(source.getPackageName()))return null;
        ActivityInfo launcherInfo=context.getPackageManager().getActivityInfo(source,0);
        if(launcherInfo.launchMode!=2)return null;
        ActivityInfo info=registeredHome(context);
        if(launcherInfo.applicationInfo==null||info.applicationInfo.uid!=launcherInfo.applicationInfo.uid
            ||!info.applicationInfo.sourceDir.equals(launcherInfo.applicationInfo.sourceDir))
            throw new IOException("OWNED_HOME_INSTALLED_IDENTITY_CHANGED");
        return new Intent(BackgroundOwnedSingleTask.ACTION).setComponent(new ComponentName(info.packageName,info.name))
            .setPackage(BackgroundOwnedSingleTask.PACKAGE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
    }

    static void recheckHome(Context context, BackgroundOwnedTaskPolicy.Activity expected) throws Exception {
        ActivityInfo info=registeredHome(context);
        if(info.applicationInfo.uid!=expected.uid||!info.applicationInfo.sourceDir.equals(expected.sourceDir)
            ||!(info.packageName+"/"+info.name).equals(expected.component)||info.launchMode!=expected.launchMode
            ||info.documentLaunchMode!=expected.documentLaunchMode||info.flags!=expected.manifestFlags
            ||info.enabled!=expected.enabled||info.exported!=expected.exported
            ||info.applicationInfo.enabled!=expected.applicationEnabled
            ||!java.util.Objects.equals(info.targetActivity,expected.targetActivity)
            ||!java.util.Objects.equals(info.permission,expected.permission))
            throw new IOException("OWNED_HOME_ACTIVITY_INFO_CHANGED");
    }

    private static ActivityInfo registeredHome(Context context) throws Exception {
        Intent query=new Intent(BackgroundOwnedSingleTask.ACTION).setPackage(BackgroundOwnedSingleTask.PACKAGE);
        List<ResolveInfo> result=context.getPackageManager().queryIntentActivities(query,PackageManager.MATCH_DEFAULT_ONLY);
        if(result==null||result.size()!=1||result.get(0)==null)throw new IOException("OWNED_HOME_REGISTRATION_NOT_UNIQUE");
        ActivityInfo info=result.get(0).activityInfo;
        if(info==null||info.applicationInfo==null||!BackgroundOwnedSingleTask.PACKAGE.equals(info.packageName)
            ||!BackgroundOwnedSingleTask.PACKAGE.equals(info.applicationInfo.packageName)
            ||!BackgroundOwnedSingleTask.COMPONENT.equals(info.packageName+"/"+info.name)
            ||!info.enabled||!info.applicationInfo.enabled||!info.exported||info.targetActivity!=null
            ||info.launchMode!=2||info.documentLaunchMode!=0||info.applicationInfo.sourceDir==null)
            throw new IOException("OWNED_HOME_REGISTRATION_CHANGED");
        return info;
    }

    @Override public Object newCookie(){return new Binder();}
    @Override public void guard() throws Exception {activeCheck.check();}
    @Override public List<BackgroundOwnedSingleTask.Task> roots() throws Exception {return rows(roots.invoke(organizer,display,null));}
    @Override public List<BackgroundOwnedSingleTask.Task> children(Object token) throws Exception {
        return rows(children.invoke(organizer,wrapper(token),null));
    }
    @Override public void createRoot(Object cookie) throws Exception {
        activeCheck.check();create.invoke(organizer,display,fullscreen,(IBinder)cookie,false);
    }
    @Override public void reparentEmpty(Object child,Object parent) throws Exception {
        activeCheck.check();Object transaction=transactionType.getConstructor().newInstance();
        reparent.invoke(transaction,wrapper(child),wrapper(parent),false);
        apply.invoke(windowOrganizer,transaction);
    }
    @Override public void bindLaunch(Object root,int rootId,Object cookie) throws Exception {
        setTask.invoke(options,rootId);setRoot.invoke(options,wrapper(root));setCookie.invoke(options,(IBinder)cookie);
        ActivityOptions roundtrip=(ActivityOptions)ActivityOptions.class.getMethod("fromBundle",android.os.Bundle.class)
            .invoke(null,options.toBundle());
        Object actualRoot=ActivityOptions.class.getMethod("getLaunchRootTask").invoke(roundtrip);
        Object actualCookie=ActivityOptions.class.getMethod("getLaunchCookie").invoke(roundtrip);
        int actualTask=((Integer)ActivityOptions.class.getMethod("getLaunchTaskId").invoke(roundtrip)).intValue();
        if(actualTask!=rootId||actualRoot==null||!root.equals(tokenBinder.invoke(actualRoot))
            ||!cookie.equals(actualCookie)||roundtrip.getLaunchDisplayId()!=display)
            throw new IOException("OWNED_TASK_OPTIONS_ROUNDTRIP_MISMATCH");
    }
    @Override public void removeOwnedLeaf(Object token) throws Exception {
        locationCheck.check();Object transaction=transactionType.getConstructor().newInstance();
        // AOSP REMOVE_TASK requests killProcess=true and removes recents. The proof records this.
        // Only the coordinator's new, fully-bound leaf token reaches this operation.
        remove.invoke(transaction,wrapper(token));apply.invoke(windowOrganizer,transaction);
    }
    @Override public boolean deleteOwnedContainer(Object token) throws Exception {
        locationCheck.check();return Boolean.TRUE.equals(delete.invoke(organizer,wrapper(token)));
    }
    @Override public Set<Integer> liveTaskIds() throws Exception {return taskIds(false);}
    @Override public Set<Integer> liveLeafTaskIds() throws Exception {return taskIds(true);}
    @Override public String activitiesDump() throws Exception {return dump("activities");}
    @Override public String recentsDump() throws Exception {return dump("recents");}

    private Object wrapper(Object binder) throws IOException {
        Object wrapper=tokenWrappers.get(binder);
        if(wrapper==null)throw new IOException("OWNED_TASK_TOKEN_NOT_OBSERVED");return wrapper;
    }
    private Set<Integer> taskIds(boolean onlyLeaves) throws Exception {
        Object value=allRoots.invoke(activityTasks);
        if(!(value instanceof List)||((List<?>)value).size()>256)throw new IOException("OWNED_GLOBAL_TASK_QUERY_INCOMPLETE");
        Set<Integer> result=new LinkedHashSet<Integer>(),leafIds=new LinkedHashSet<Integer>();int count=0;
        for(Object root:(List<?>)value){
            if(root==null)throw new IOException("OWNED_GLOBAL_TASK_QUERY_INCOMPLETE");
            int id=integer(root,"taskId");if(id<=0)throw new IOException("OWNED_GLOBAL_TASK_ID_INVALID");
            if(!onlyLeaves)result.add(id);
            Object ids=field(root,"childTaskIds");
            if(!(ids instanceof int[]))throw new IOException("OWNED_GLOBAL_TASK_CHILDREN_UNKNOWN");
            for(int child:(int[])ids){
                if(child<=0||!leafIds.add(child)||++count>2048)throw new IOException("OWNED_GLOBAL_LEAF_IDS_INVALID");
                result.add(child);
            }
        }
        return result;
    }
    private List<BackgroundOwnedSingleTask.Task> rows(Object value) throws Exception {
        if(!(value instanceof List)||((List<?>)value).size()>2048)throw new IOException("OWNED_TASK_ROWS_UNAVAILABLE");
        ArrayList<BackgroundOwnedSingleTask.Task> out=new ArrayList<BackgroundOwnedSingleTask.Task>();
        for(Object row:(List<?>)value){
            if(row==null)throw new IOException("OWNED_TASK_ROW_NULL");
            Object token=field(row,"token");Object binder=token==null?null:tokenBinder.invoke(token);
            if(!(binder instanceof IBinder))throw new IOException("OWNED_TASK_TOKEN_INVALID");
            tokenWrappers.put(binder,token);
            Object rawCookies=field(row,"launchCookies");
            if(!(rawCookies instanceof List)||((List<?>)rawCookies).size()>128)throw new IOException("OWNED_TASK_COOKIES_INVALID");
            ArrayList<Object> cookies=new ArrayList<Object>();
            for(Object c:(List<?>)rawCookies){if(!(c instanceof IBinder))throw new IOException("OWNED_TASK_COOKIE_INVALID");cookies.add(c);}
            Object rawIntent=field(row,"baseIntent");
            if(!(rawIntent instanceof Intent))throw new IOException("OWNED_TASK_BASE_INTENT_UNKNOWN");
            Object rawInfo=field(row,"topActivityInfo");int topUid=-1;
            String top=component(field(row,"topActivity"));
            if(rawInfo!=null){
                if(!(rawInfo instanceof ActivityInfo))throw new IOException("OWNED_TASK_TOP_INFO_INVALID");
                ActivityInfo info=(ActivityInfo)rawInfo;
                if(info.applicationInfo==null||info.packageName==null||info.name==null
                    ||!info.packageName.equals(info.applicationInfo.packageName)
                    ||!(info.packageName+"/"+info.name).equals(top))throw new IOException("OWNED_TASK_TOP_INFO_IDENTITY_INVALID");
                topUid=info.applicationInfo.uid;
            }else if(top!=null)throw new IOException("OWNED_TASK_TOP_UID_UNKNOWN");
            out.add(new BackgroundOwnedSingleTask.Task(integer(row,"taskId"),integer(row,"displayId"),
                integer(row,"userId"),integer(row,"parentTaskId"),integer(row,"effectiveUid"),topUid,
                integer(row,"numActivities"),binder,cookies,component(((Intent)rawIntent).getComponent()),
                component(field(row,"baseActivity")),top,component(field(row,"realActivity")),
                component(field(row,"origActivity")),bool(row,"isRunning"),bool(row,"isVisible")));
        }
        return out;
    }
    private static Object field(Object row,String name) throws Exception {return row.getClass().getField(name).get(row);}
    private static int integer(Object row,String name) throws Exception {Object value=field(row,name);if(!(value instanceof Integer))throw new IOException("OWNED_TASK_FIELD_NOT_INTEGER");return (Integer)value;}
    private static boolean bool(Object row,String name) throws Exception {Object value=field(row,name);if(!(value instanceof Boolean))throw new IOException("OWNED_TASK_FIELD_NOT_BOOLEAN");return (Boolean)value;}
    private static String component(Object value) throws IOException {
        if(value==null)return null;if(!(value instanceof ComponentName))throw new IOException("OWNED_TASK_COMPONENT_INVALID");
        ComponentName c=(ComponentName)value;return c.getPackageName()+"/"+c.getClassName();
    }

    private String dump(String command) throws Exception {
        long remaining=deadline.getAsLong()-SystemClock.elapsedRealtime();
        if(remaining<=0)throw new IOException("OWNED_TASK_DUMP_DEADLINE");
        final ParcelFileDescriptor[] pipe=ParcelFileDescriptor.createPipe();
        final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        final AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
        Thread reader=new Thread(()->{
            try(ParcelFileDescriptor.AutoCloseInputStream in=new ParcelFileDescriptor.AutoCloseInputStream(pipe[0])){
                byte[] buffer=new byte[8192];int n;
                while((n=in.read(buffer))!=-1){
                    if(bytes.size()+n>BackgroundOwnedSingleTask.MAX_DUMP_BYTES)throw new IOException("OWNED_TASK_DUMP_SIZE");
                    bytes.write(buffer,0,n);
                }
            }catch(Throwable e){failure.set(e);}
        },"HeptaOwnedTaskDump");
        reader.setDaemon(true);reader.start();
        try {
            activityManager.dump(pipe[1].getFileDescriptor(),new String[]{"-a",command});
        } finally {pipe[1].close();}
        remaining=deadline.getAsLong()-SystemClock.elapsedRealtime();
        if(remaining>0)reader.join(remaining);
        if(reader.isAlive()) {pipe[0].close();throw new IOException("OWNED_TASK_DUMP_DEADLINE");}
        if(failure.get()!=null)throw new IOException("OWNED_TASK_DUMP_READ_FAILED",failure.get());
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
    }
}
