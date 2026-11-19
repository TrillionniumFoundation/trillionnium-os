package org.trillionnium.hepta.background;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.hardware.display.DisplayManager;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Root census only. No display/task mutation, input, app launch, wake, journal
 * mutation or external-PID signal API is present. The existing fixed Settings
 * boot reader owns and closes only its own read-only command child.
 * One process retains the actual task token
 * across the before sample and both independent current-absence samples. */
public final class ControllerDisplayHandoffMain {
    private ControllerDisplayHandoffMain(){}
    private static void need(boolean b,String code)throws Exception{ControllerDisplayHandoff.need(b,code);}
    private static long now(){return SystemClock.elapsedRealtime();}
    private static Object field(Object o,String key)throws Exception{return o.getClass().getField(key).get(o);}
    private static int integer(Object o,String key)throws Exception{Object v=field(o,key);need(v instanceof Integer,"HANDOFF_FRAMEWORK_INTEGER_"+key);return (Integer)v;}
    private static boolean bool(Object o,String key)throws Exception{Object v=field(o,key);need(v instanceof Boolean,"HANDOFF_FRAMEWORK_BOOLEAN_"+key);return (Boolean)v;}
    private static String component(Object v)throws Exception{need(v==null||v instanceof ComponentName,"HANDOFF_COMPONENT_TYPE");return v==null?null:((ComponentName)v).flattenToString();}
    private static JSONObject parse(byte[] raw)throws Exception{return new JSONObject(new String(raw,StandardCharsets.UTF_8));}
    public static void main(String[] args){
        ControllerDisplayHandoff.Request request=null;Reader active=null;
        final ProfileRecoveryBootCount bootCount=new ProfileRecoveryBootCount(SystemClock::elapsedRealtime);
        try{
            need(android.os.Process.myUid()==0&&android.os.Build.VERSION.SDK_INT==36&&args.length==2&&"--request".equals(args[0]),"HANDOFF_ROOT_ARGUMENTS");
            request=ControllerDisplayHandoff.fromWire(args[1]);final ControllerDisplayHandoff.Request bound=request;
            Thread watchdog=new Thread(()->{
                while(now()<bound.deadline)try{Thread.sleep(Math.max(1,Math.min(50,bound.deadline-now())));}catch(InterruptedException ignored){}
                // The existing owner closes its own fixed read-only child before
                // this reader exits; no discovered or unrelated PID is signalled.
                try{bootCount.abortForDeadline();}catch(Throwable ignored){}
                finally{Runtime.getRuntime().halt(70);}
            },"HeptaControllerHandoffDeadline");watchdog.setDaemon(true);watchdog.start();
            if(Looper.getMainLooper()==null)Looper.prepareMainLooper();
            Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
            Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
            Context shell=system.createPackageContext("com.android.shell",0);
            Reader reader=new Reader(shell,request,bootCount);active=reader;JSONObject before=reader.before();
            emit(before); // The App persists PENDING only after independently checking this full record.
            JSONArray absent=new JSONArray();long last=before.getJSONObject("sample").getLong("finished_elapsed_ms");
            while(absent.length()<2){
                reader.fence();while(now()<=last){reader.fence();Thread.sleep(1);}
                JSONObject sample;
                try{sample=reader.sample(false);}catch(CallerRemovedDuringCensus incomplete){
                    absent=new JSONArray();reader.fence();continue;
                }
                last=sample.getLong("finished_elapsed_ms");
                if(reader.absent(sample))absent.put(sample);else absent=new JSONArray();
                if(absent.length()<2)Thread.sleep(Math.min(100,Math.max(1,request.deadline-now())));
            }
            reader.requireInstallation();reader.fence();
            JSONObject complete=ControllerDisplayHandoff.envelope(ControllerDisplayHandoff.COMPLETE,request)
                    .put("before_sha256",ControllerDisplayHandoff.sha(before.toString().getBytes(StandardCharsets.UTF_8)))
                    .put("reader_pid",reader.pid).put("reader_start_ticks",reader.ticks).put("absence_samples",absent)
                    .put("incomplete_censuses",reader.incompleteCensuses)
                    .put("current_absence_verified",true).put("business_success",false);
            ControllerDisplayHandoff.validateComplete(complete,before,request,now(),reader.boot());
            // Publication follows the original boot-reader's actual child exit
            // and EOF, never an in-flight command or a supplied boot number.
            bootCount.abortForDeadline();reader.fence();emit(complete);System.exit(0);
        }catch(Throwable failure){
            try{bootCount.abortForDeadline();}catch(Throwable closeFailure){if(closeFailure!=failure)failure.addSuppressed(closeFailure);}
            try{emit(new JSONObject().put("schema","hepta.controller-display-handoff.failure.v1")
                    .put("request_sha256",request==null?JSONObject.NULL:request.requestSha)
                    .put("error_class",failure.getClass().getName()).put("error",String.valueOf(failure.getMessage()))
                    .put("incomplete_censuses",active==null?new JSONArray():active.incompleteCensuses)
                    .put("current_absence_verified",false).put("business_success",false));}catch(Throwable ignored){}
            System.exit(70);
        }
    }
    private static final class CallerRemovedDuringCensus extends IOException {
        private static final long serialVersionUID=1L;
        CallerRemovedDuringCensus(){super("HANDOFF_CALLER_REMOVED_DURING_CENSUS_NOT_ABSENCE");}
    }
    private static void emit(JSONObject value)throws Exception{
        String text=value.toString();need(text.getBytes(StandardCharsets.UTF_8).length<=ControllerDisplayHandoff.MAX_OUTPUT,"HANDOFF_OUTPUT_BOUND");
        System.out.println(text);System.out.flush();need(!System.out.checkError(),"HANDOFF_OUTPUT_WRITE_FAILED");
    }
    private static final class Reader {
        final Context context;final ControllerDisplayHandoff.Request r;final Object atm,wm,dms;
        final ProfileRecoveryBootCount bootCount;
        final DisplayManager dm;final Method displayIds,displayInfo;final int pid;final long ticks;
        IBinder taskToken;JSONObject baseline,beforeProof;String recentToken;boolean displayGone,taskGone;
        final JSONArray incompleteCensuses=new JSONArray();
        Reader(Context context,ControllerDisplayHandoff.Request r,ProfileRecoveryBootCount bootCount)throws Exception{
            this.context=context;this.r=r;this.bootCount=bootCount;pid=android.os.Process.myPid();ticks=process(pid,0,null);
            boot();
            atm=Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
            wm=Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
            dm=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
            Object displayBinder=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"display");
            need(displayBinder instanceof IBinder,"HANDOFF_DISPLAY_SERVICE_BINDER");
            dms=Class.forName("android.hardware.display.IDisplayManager$Stub").getMethod("asInterface",IBinder.class).invoke(null,displayBinder);
            Class<?> type=Class.forName("android.hardware.display.IDisplayManager");
            displayIds=type.getMethod("getDisplayIds",boolean.class);displayInfo=type.getMethod("getDisplayInfo",int.class);
            need(atm!=null&&wm!=null&&dm!=null&&dms!=null,"HANDOFF_SERVICES_UNAVAILABLE");fence();requireInstallation();
        }
        int boot()throws Exception{
            // Standalone root app_process has no registered IApplicationThread.
            // Reuse the qualified owned SettingsService read and its original
            // bounded deadline, rather than ContentResolver or a default value.
            PublicOwnGroupBootIdentity.requireCurrent(bootCount,r.boot,now(),r.deadline);return r.boot;
        }
        // Boot was actually read by this same process before any census and is
        // read again at before/final publication. Hot per-field checks only
        // enforce the original absolute clock fence; they spawn no children.
        void fence()throws Exception{r.fence(now(),r.boot);}
        void requireInstallation()throws Exception{
            need(ControllerDisplayHandoff.same(r.installation(),RecoveryControllerIdentity.read(context,r.locator.uid,r.deadline)),"HANDOFF_INSTALLATION_CHANGED");
        }
        JSONObject before()throws Exception{
            baseline=sample(true);JSONObject out=ControllerDisplayHandoff.envelope(ControllerDisplayHandoff.BEFORE,r)
                    .put("reader_uid",0).put("reader_pid",pid).put("reader_start_ticks",ticks).put("sample",baseline);
            beforeProof=ControllerDisplayHandoff.validateBefore(out,r,now(),boot());return beforeProof;
        }
        JSONArray displays(boolean waiting)throws Exception{
            fence();Object value=displayIds.invoke(dms,true);need(value instanceof int[],"HANDOFF_DISPLAY_IDS_TYPE");
            int[] ids=((int[])value).clone();need(ids.length>=2&&ids.length<=64,"HANDOFF_DISPLAY_IDS_BOUND");
            TreeMap<Integer,JSONObject> rows=new TreeMap<Integer,JSONObject>();
            for(int id:ids){
                fence();need(id>=0&&!rows.containsKey(id),"HANDOFF_DISPLAY_ID_DUPLICATE");Object info=displayInfo.invoke(dms,id);
                if(info==null&&waiting&&beforeProof!=null&&id==r.locator.display)continue;
                need(info!=null&&integer(info,"displayId")==id,"HANDOFF_DISPLAY_INFO_UNKNOWN");
                Object name=field(info,"name"),unique=field(info,"uniqueId"),owner=field(info,"ownerPackageName");
                need(name instanceof String&&unique instanceof String&&(owner==null||owner instanceof String),"HANDOFF_DISPLAY_IDENTITY_UNKNOWN");
                rows.put(id,new JSONObject().put("id",id).put("name",name).put("unique_id",unique)
                        .put("type",integer(info,"type")).put("flags",integer(info,"flags")).put("state",integer(info,"state"))
                        .put("group",integer(info,"displayGroupId")).put("owner_uid",integer(info,"ownerUid"))
                        .put("owner_package",owner==null?JSONObject.NULL:owner)
                        .put("width",integer(info,"logicalWidth")).put("height",integer(info,"logicalHeight"))
                        .put("density",integer(info,"logicalDensityDpi")).put("rotation",integer(info,"rotation")));
            }
            Object second=displayIds.invoke(dms,true);need(second instanceof int[],"HANDOFF_DISPLAY_IDS_TYPE");
            int[] a=ids.clone(),b=((int[])second).clone();Arrays.sort(a);Arrays.sort(b);
            if(waiting&&beforeProof!=null&&ControllerDisplayHandoff.onlyCallerRemoved(a,b,r.locator.display)){
                need(!displayGone,"HANDOFF_CALLER_DISPLAY_REAPPEARED");displayGone=true;
                JSONArray prior=baseline.getJSONArray("displays");
                for(int survivor:b){JSONObject expected=null;
                    for(int i=0;i<prior.length();i++)if(prior.getJSONObject(i).getInt("id")==survivor)expected=prior.getJSONObject(i);
                    need(expected!=null&&ControllerDisplayHandoff.same(expected,rows.get(survivor)),"HANDOFF_OTHER_DISPLAY_CHANGED_DURING_RELEASE");
                }
                incompleteCensuses.put(new JSONObject().put("reason","exact_caller_removed_during_display_census")
                        .put("observed_elapsed_ms",now()).put("ids_before",new JSONArray(a)).put("ids_after",new JSONArray(b))
                        .put("complete",false).put("counts_as_absence",false));
                throw new CallerRemovedDuringCensus();
            }
            need(Arrays.equals(a,b)&&rows.size()==ids.length&&rows.containsKey(0)&&rows.containsKey(1),"HANDOFF_DISPLAY_CENSUS_CHANGED");return new JSONArray(rows.values());
        }
        JSONObject sample(boolean first)throws Exception{
            fence();long started=now();long birth=process(r.locator.pid,r.locator.uid,ControllerDisplayHandoff.PACKAGE);
            need(birth==r.locator.startTicks,"HANDOFF_APP_GENERATION_CHANGED");JSONArray displays=displays(!first);
            Object raw=Class.forName("android.app.IActivityTaskManager").getMethod("getAllRootTaskInfos").invoke(atm);
            // Same complete RootTaskInfo response supplies both the strict global
            // parallel arrays and the caller's actual TaskInfo/token fields.
            need(raw instanceof List&&((List<?>)raw).size()<=ProfileTaskPolicy.MAX_ROOTS,"HANDOFF_ROOT_CENSUS_BOUND");
            List<ProfileTaskPolicy.Root> roots=new ArrayList<ProfileTaskPolicy.Root>();Object own=null;
            for(Object row:(List<?>)raw){
                need(row!=null,"HANDOFF_ROOT_UNKNOWN");Object ids=field(row,"childTaskIds"),users=field(row,"childTaskUserIds"),names=field(row,"childTaskNames"),bounds=field(row,"childTaskBounds");
                need(ids instanceof int[]&&users instanceof int[]&&names instanceof String[]&&bounds instanceof android.graphics.Rect[],"HANDOFF_ROOT_ARRAYS_UNKNOWN");
                android.graphics.Rect[] rectangles=(android.graphics.Rect[])bounds;int[][] geometry=new int[rectangles.length][];
                for(int i=0;i<rectangles.length;i++){android.graphics.Rect q=rectangles[i];need(q!=null,"HANDOFF_ROOT_BOUNDS_UNKNOWN");geometry[i]=new int[]{q.left,q.top,q.right,q.bottom};}
                int id=integer(row,"taskId"),display=integer(row,"displayId");
                roots.add(new ProfileTaskPolicy.Root(id,display,integer(row,"userId"),integer(row,"numActivities"),bool(row,"visible"),
                        component(field(row,"baseActivity")),component(field(row,"topActivity")),(int[])ids,(int[])users,(String[])names,geometry));
                if(id==r.locator.task){need(own==null&&display==r.locator.display&&!taskGone,"HANDOFF_CALLER_TASK_RELOCATED");own=row;}
                if(display==r.locator.display)need(id==r.locator.task,"HANDOFF_FOREIGN_ROOT_ON_CALLER_DISPLAY");
            }
            ProfileTaskPolicy.Snapshot census=new ProfileTaskPolicy.Snapshot(roots);
            Set<Integer> rootIds=new TreeSet<Integer>();for(ProfileTaskPolicy.Root row:roots)rootIds.add(row.id);
            for(ProfileTaskPolicy.Leaf row:census.leaves.values()){
                if(row.display==r.locator.display)need(row.id==r.locator.task&&row.parent==r.locator.task&&row.user==0,"HANDOFF_FOREIGN_LEAF_ON_CALLER_DISPLAY");
                if(row.id==r.locator.task)need(own!=null&&row.display==r.locator.display&&row.parent==r.locator.task,"HANDOFF_CALLER_LEAF_RELOCATED");
            }
            JSONObject task=own==null?null:task(own,first);if(own==null)taskGone=true;
            String recentsRaw=BackgroundTaskOrganizer.profileRecents(()->r.deadline);
            PublicOwnGroupPhysicalFence.RecentCensus recents=PublicOwnGroupPhysicalFence.inspectRecents(recentsRaw);
            PublicOwnGroupPhysicalFence.RecentRecord recent=recents.records.get(r.locator.task);
            if(first)need(recent!=null,"HANDOFF_CALLER_RECENT_MISSING");
            if(recent!=null){
                need(recent.task==r.locator.task&&recent.root==r.locator.task&&recent.user==0&&recent.uid==r.locator.uid
                        &&recent.display==r.locator.display&&ControllerDisplayHandoff.COMPONENT.equals(recent.base)
                        &&ControllerDisplayHandoff.COMPONENT.equals(recent.activity),"HANDOFF_CALLER_RECENT_IDENTITY");
                if(first)recentToken=recent.token;else need(recent.token.equals(recentToken),"HANDOFF_CALLER_RECENT_REUSED");
            }else need(!recents.hiddenLabels.containsKey(r.locator.task),"HANDOFF_CALLER_HIDDEN_IDENTITY_UNKNOWN");
            for(PublicOwnGroupPhysicalFence.RecentRecord row:recents.records.values())
                if(row.display==r.locator.display||row.root==r.locator.task)need(row.task==r.locator.task,"HANDOFF_FOREIGN_RECENT_ON_CALLER_DISPLAY");
            String history=recents.historyExcept(Collections.singleton(r.locator.task));
            Map<Integer,String> physical=PublicOwnGroupPhysicalReader.read(wm,dm,0,()->r.deadline);
            need(process(r.locator.pid,r.locator.uid,ControllerDisplayHandoff.PACKAGE)==birth,"HANDOFF_APP_GENERATION_CHANGED");fence();
            JSONObject sample=new JSONObject().put("schema",ControllerDisplayHandoff.SAMPLE).put("complete",true)
                    .put("started_elapsed_ms",started).put("finished_elapsed_ms",now())
                    .put("app_uid",r.locator.uid).put("app_pid",r.locator.pid).put("app_start_ticks",birth)
                    .put("displays",displays).put("controller_task",task==null?JSONObject.NULL:task).put("controller_active_complete",first)
                    .put("root_ids",new JSONArray(rootIds)).put("leaf_ids",new JSONArray(new TreeSet<Integer>(census.leaves.keySet())))
                    .put("recent_ids",new JSONArray(new TreeSet<Integer>(recents.allIds)))
                    .put("physical",new JSONObject().put("0",physical.get(0)).put("1",physical.get(1)))
                    .put("foreign_history_sha256",ControllerDisplayHandoff.sha(history.getBytes(StandardCharsets.UTF_8)))
                    .put("recents_raw_sha256",recents.rawSha256);
            if(!first){
                ControllerDisplayHandoff.validateWaiting(sample,beforeProof,r);JSONObject current=null;
                for(int i=0;i<displays.length();i++)if(displays.getJSONObject(i).getInt("id")==r.locator.display)current=displays.getJSONObject(i);
                if(current==null)displayGone=true;
                else need(!displayGone,"HANDOFF_CALLER_DISPLAY_REAPPEARED");
            }
            return sample;
        }
        JSONObject task(Object row,boolean first)throws Exception{
            Object token=field(row,"token");need(token!=null,"HANDOFF_TASK_TOKEN_UNKNOWN");
            Object binder=Class.forName("android.window.WindowContainerToken").getMethod("asBinder").invoke(token);
            need(binder instanceof IBinder,"HANDOFF_TASK_TOKEN_UNKNOWN");if(first)taskToken=(IBinder)binder;else need(taskToken.equals(binder),"HANDOFF_TASK_TOKEN_CHANGED");
            int uid=integer(row,"effectiveUid"),user=integer(row,"userId"),count=integer(row,"numActivities");
            Object intent=field(row,"baseIntent");need(intent instanceof Intent,"HANDOFF_TASK_INTENT_UNKNOWN");
            String base=component(field(row,"baseActivity")),top=component(field(row,"topActivity"));
            String real=component(field(row,"realActivity")),orig=component(field(row,"origActivity"));
            String source=component(((Intent)intent).getComponent());Object rawTop=field(row,"topActivityInfo");
            boolean running=bool(row,"isRunning");
            need(uid==r.locator.uid&&user==0&&integer(row,"parentTaskId")==-1&&ControllerDisplayHandoff.COMPONENT.equals(source)
                    &&ControllerDisplayHandoff.COMPONENT.equals(real)&&(orig==null||ControllerDisplayHandoff.COMPONENT.equals(orig)),"HANDOFF_TASK_IDENTITY_CHANGED");
            if(first||count>0){
                need(count==1&&running&&ControllerDisplayHandoff.COMPONENT.equals(base)&&ControllerDisplayHandoff.COMPONENT.equals(top)
                        &&rawTop instanceof ActivityInfo,"HANDOFF_ACTIVE_TASK_INCOMPLETE");ActivityInfo info=(ActivityInfo)rawTop;
                need(info.applicationInfo!=null&&info.applicationInfo.uid==uid&&ControllerDisplayHandoff.PACKAGE.equals(info.packageName)
                        &&ControllerDisplayHandoff.PACKAGE.equals(info.applicationInfo.packageName)
                        &&ControllerDisplayHandoff.COMPONENT.equals(info.packageName+"/"+info.name),"HANDOFF_TOP_UID_UNKNOWN");
                if(first)need(bool(row,"isVisible"),"HANDOFF_CALLER_NOT_VISIBLE");
            }else need(count==0&&!running&&base==null&&top==null&&rawTop==null,"HANDOFF_EMPTY_TASK_UNKNOWN");
            return new JSONObject().put("id",r.locator.task).put("display",r.locator.display).put("uid",uid).put("user",user)
                    .put("parent",-1).put("token",taskToken.toString()).put("intent",source).put("real",real);
        }
        boolean absent(JSONObject s)throws Exception{
            if(!s.isNull("controller_task"))return false;
            for(int i=0;i<s.getJSONArray("displays").length();i++)if(s.getJSONArray("displays").getJSONObject(i).getInt("id")==r.locator.display)return false;
            for(String key:new String[]{"root_ids","leaf_ids","recent_ids"})for(int i=0;i<s.getJSONArray(key).length();i++)
                if(s.getJSONArray(key).getInt(i)==r.locator.task)return false;
            return true;
        }
    }
    private static byte[] proc(int pid,String leaf,int uid)throws Exception{
        need(pid>1&&("stat".equals(leaf)||"cmdline".equals(leaf)),"HANDOFF_PROC_ARGUMENT");
        FileDescriptor fd=Os.open("/proc/"+pid+"/"+leaf,OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);
        try{StructStat before=Os.fstat(fd);need(OsConstants.S_ISREG(before.st_mode)&&before.st_uid==uid,"HANDOFF_PROC_UID");
            ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[1024];int n;
            while((n=Os.read(fd,buffer,0,buffer.length))>0){need(out.size()+n<=8192,"HANDOFF_PROC_BOUND");out.write(buffer,0,n);}
            StructStat after=Os.fstat(fd);need(before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_uid==after.st_uid,"HANDOFF_PROC_CHANGED");return out.toByteArray();
        }finally{Os.close(fd);}
    }
    private static long process(int pid,int uid,String pkg)throws Exception{
        byte[] first=proc(pid,"stat",uid);String text=new String(first,StandardCharsets.US_ASCII);int end=text.lastIndexOf(')');
        need(text.startsWith(pid+" (")&&end>0,"HANDOFF_PROC_STAT");String[] fields=text.substring(end+2).trim().split(" +");
        need(fields.length>=20&&!"Z".equals(fields[0])&&!"X".equals(fields[0]),"HANDOFF_PROC_NOT_LIVE");long ticks=Long.parseLong(fields[19]);need(ticks>0,"HANDOFF_PROC_TICKS");
        if(pkg!=null)need(Arrays.equals(proc(pid,"cmdline",uid),(pkg+'\0').getBytes(StandardCharsets.UTF_8)),"HANDOFF_APP_CMDLINE");
        String again=new String(proc(pid,"stat",uid),StandardCharsets.US_ASCII);int tail=again.lastIndexOf(')');
        need(again.startsWith(pid+" (")&&tail>0&&Long.parseLong(again.substring(tail+2).trim().split(" +")[19])==ticks,"HANDOFF_PROC_GENERATION_CHANGED");return ticks;
    }
}
