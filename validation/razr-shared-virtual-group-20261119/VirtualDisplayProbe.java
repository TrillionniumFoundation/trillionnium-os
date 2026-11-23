package org.trillionnium.hepta.displayprobe;

import android.app.UiAutomation;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.SparseArray;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/** Bounded shell-owned feasibility probe; no network, arbitrary RPC or model control. */
public final class VirtualDisplayProbe {
    private static File root;
    private static VirtualDisplay display;
    private static ImageReader reader;
    private static UiAutomation observer;
    private static HandlerThread observerThread;
    private static String generation;
    private static int displayId = -1;
    private static long deadline;
    private static int frames;
    private static volatile boolean closed;
    private static final Object imageLock = new Object();
    private static Image heldImage;
    private static int heldFrame;
    private static long heldSourceUptimeMs;
    private static Handler handler;
    private static final int WIDTH = 720, HEIGHT = 1280;
    // SDK 36 hidden flag values; actual acceptance is checked in dumpsys.
    private static final int FLAGS = (1 << 0) | (1 << 3) | (1 << 6) | (1 << 8)
        | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 14) | (1 << 16);

    private static final String PROFILE = "hepta.public-own-group-display-unlocked-insecure.probe.v1";
    private static final int EXPECTED_DISPLAY_FLAGS = 7040;
    private static Context shellContext;
    private static final java.util.concurrent.atomic.AtomicBoolean stopping=new java.util.concurrent.atomic.AtomicBoolean();
    private static final java.util.concurrent.atomic.AtomicBoolean closeClaim=new java.util.concurrent.atomic.AtomicBoolean();
    private static volatile long policyHeartbeat,closeStarted;
    private static volatile boolean policyMonitoring;
    private static int boundGroup=-1;
    private static String boundUniqueId;
    private static volatile OwnedDisplayPowerLease screenPowerLease;
    private static String screenPowerTag;
    private static volatile long initializationDeadline;
    private static volatile String startupStage="before_display_creation";
    private static final JSONArray initialPowerObservations=new JSONArray();

    private static boolean actualBoolean(Object value) {
        if (!(value instanceof Boolean)) throw new SecurityException("framework lock state unknown");
        return ((Boolean)value).booleanValue();
    }

    private static JSONObject policySnapshot() throws Exception {
        long begin = SystemClock.elapsedRealtime();
        int uid = android.os.Process.myUid(), pid = android.os.Process.myPid();
        Object contextUser = Context.class.getMethod("getUserId").invoke(shellContext);
        if (!(contextUser instanceof Integer) || ((Integer)contextUser).intValue() != 0)
            throw new SecurityException("default user context unavailable");
        Object activity=Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
        if(activity==null)throw new SecurityException("current user service unavailable");
        Object currentUser=Class.forName("android.app.IActivityManager").getMethod("getCurrentUserId").invoke(activity);
        if(!(currentUser instanceof Integer))throw new SecurityException("current user identity unavailable");
        Object windows = Class.forName("android.view.WindowManagerGlobal")
            .getMethod("getWindowManagerService").invoke(null);
        Class<?> wm = Class.forName("android.view.IWindowManager");
        Object binder = Class.forName("android.os.ServiceManager")
            .getMethod("getService",String.class).invoke(null,"trust");
        if (!(binder instanceof android.os.IBinder) || windows == null)
            throw new SecurityException("framework lock services unavailable");
        Object trust = Class.forName("android.app.trust.ITrustManager$Stub")
            .getMethod("asInterface",android.os.IBinder.class).invoke(null,binder);
        Class<?> trustType = Class.forName("android.app.trust.ITrustManager");
        if (trust == null) throw new SecurityException("framework trust unavailable");
        // Query the default device explicitly. A virtual-device context is not credential evidence.
        boolean keyguardSecure = actualBoolean(wm.getMethod("isKeyguardSecure",int.class).invoke(windows,0));
        boolean deviceSecure = actualBoolean(trustType.getMethod("isDeviceSecure",int.class,int.class).invoke(trust,0,0));
        boolean deviceLocked = actualBoolean(trustType.getMethod("isDeviceLocked",int.class,int.class).invoke(trust,0,0));
        boolean keyguardLocked = actualBoolean(wm.getMethod("isKeyguardLocked").invoke(windows));
        return new JSONObject().put("profile",PROFILE).put("uid",uid).put("pid",pid)
            .put("source","direct_framework_binder").put("context_user_id",0).put("device_id",0)
            .put("current_user_id",((Integer)currentUser).intValue())
            .put("keyguard_secure",keyguardSecure).put("device_secure",deviceSecure)
            .put("keyguard_locked",keyguardLocked).put("device_locked",deviceLocked)
            .put("add_trusted_display_permission",shellContext.checkPermission("android.permission.ADD_TRUSTED_DISPLAY",pid,uid))
            .put("add_always_unlocked_display_permission",shellContext.checkPermission("android.permission.ADD_ALWAYS_UNLOCKED_DISPLAY",pid,uid))
            .put("internal_system_window_permission",shellContext.checkPermission("android.permission.INTERNAL_SYSTEM_WINDOW",pid,uid))
            .put("observed_started_elapsed_ms",begin).put("observed_ended_elapsed_ms",SystemClock.elapsedRealtime());
    }

    private static void requireInsecure(JSONObject policy) throws Exception {
        int uid=policy.getInt("uid");
        if ((uid!=0 && uid!=2000) || policy.getInt("context_user_id")!=0 || policy.getInt("device_id")!=0 || policy.getInt("current_user_id")!=0
                || !"direct_framework_binder".equals(policy.getString("source"))
                || policy.getBoolean("keyguard_secure") || policy.getBoolean("device_secure") || policy.getBoolean("device_locked")
                || policy.getInt("add_trusted_display_permission")!=0
                || policy.getInt("add_always_unlocked_display_permission")!=0
                || policy.getInt("internal_system_window_permission")!=0)
            throw new SecurityException("protected public display capability unavailable");
    }

    private static Object displayInfo(android.view.Display value,int expectedId) throws Exception {
        if(value==null)throw new SecurityException("display information unavailable: display_id="+expectedId+", stage=getDisplay, result=null");
        if(!value.isValid())throw new SecurityException("display information unavailable: display_id="+expectedId+", stage=isValid, result=false");
        if(value.getDisplayId()!=expectedId)throw new SecurityException("display identity differs: display_id="+expectedId);
        Class<?> kind=Class.forName("android.view.DisplayInfo");Object info=kind.getDeclaredConstructor().newInstance();
        if(!Boolean.TRUE.equals(android.view.Display.class.getMethod("getDisplayInfo",kind).invoke(value,info)))
            throw new SecurityException("display information unavailable: display_id="+expectedId+", stage=getDisplayInfo, result=false_or_unknown");
        return info;
    }

    /** Diagnostic facts only: neither a null object nor an exception is an admission proof. */
    private static JSONObject physicalDisplayAccess(DisplayManager dm) throws Exception {
        JSONArray observations=new JSONArray();
        for(int id:new int[]{0,1}){
            JSONObject row=new JSONObject().put("requested_display_id",id).put("source","android.hardware.display.DisplayManager.getDisplay")
                .put("group_identity_verified",false);
            String stage="service";
            try{
                if(dm==null)throw new SecurityException("display manager unavailable");
                stage="getDisplay";android.view.Display value=dm.getDisplay(id);
                row.put("get_display_null",value==null);
                if(value==null){row.put("status","NO_DISPLAY_OBJECT");observations.put(row);continue;}
                stage="isValid";boolean valid=value.isValid();row.put("is_valid",valid).put("actual_display_id",value.getDisplayId());
                if(!valid){row.put("status","INVALID_DISPLAY_OBJECT");observations.put(row);continue;}
                stage="public_display_properties";row.put("flags",value.getFlags()).put("state",value.getState()).put("name",value.getName());
                stage="getDisplayInfo";Object info=displayInfo(value,id);Class<?> kind=Class.forName("android.view.DisplayInfo");
                stage="display_info_fields";row.put("display_info_flags",kind.getField("flags").getInt(info))
                    .put("display_group_id",kind.getField("displayGroupId").getInt(info)).put("display_type",kind.getField("type").getInt(info))
                    .put("owner_uid",kind.getField("ownerUid").getInt(info)).put("unique_id",kind.getField("uniqueId").get(info))
                    .put("owner_package",kind.getField("ownerPackageName").get(info)).put("group_identity_verified",true).put("status","READBACK_OBSERVED");
            }catch(Throwable failure){
                Throwable cause=failure;
                while(cause instanceof java.lang.reflect.InvocationTargetException && ((java.lang.reflect.InvocationTargetException)cause).getCause()!=null)
                    cause=((java.lang.reflect.InvocationTargetException)cause).getCause();
                row.put("status","READBACK_ERROR").put("error_stage",stage).put("error_type",cause.getClass().getName())
                    .put("error_message",String.valueOf(cause.getMessage()));
            }
            observations.put(row);
        }
        return new JSONObject().put("schema","hepta.physical-display-access-capability.v1").put("process_uid",android.os.Process.myUid())
            .put("observations",observations).put("virtual_display_created",false).put("task_started",false)
            .put("is_creation_admission_proof",false);
    }

    /** Same kernel caller and ordinary Binder API. A null or denial stays a diagnostic failure. */
    private static JSONObject directPhysicalDisplayAccess() throws Exception {
        JSONArray observations=new JSONArray();
        for(int id:new int[]{0,1}){
            JSONObject row=new JSONObject().put("requested_display_id",id)
                .put("source","android.hardware.display.IDisplayManager.getDisplayInfo")
                .put("display_info_read_completed",false);
            String stage="display_service";
            try{
                Object binder=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"display");
                if(!(binder instanceof android.os.IBinder))throw new SecurityException("display service unavailable");
                stage="display_interface";Object manager=Class.forName("android.hardware.display.IDisplayManager$Stub")
                    .getMethod("asInterface",android.os.IBinder.class).invoke(null,binder);
                if(manager==null)throw new SecurityException("display interface unavailable");
                stage="getDisplayInfo";Object info=Class.forName("android.hardware.display.IDisplayManager")
                    .getMethod("getDisplayInfo",int.class).invoke(manager,id);
                row.put("binder_returned_null",info==null);
                if(info==null){row.put("status","BINDER_RETURNED_NULL");observations.put(row);continue;}
                stage="display_info_fields";Class<?> kind=Class.forName("android.view.DisplayInfo");
                if(!kind.isInstance(info))throw new SecurityException("display info type unavailable");
                row.put("display_info_flags",kind.getField("flags").getInt(info))
                    .put("display_group_id",kind.getField("displayGroupId").getInt(info)).put("display_type",kind.getField("type").getInt(info))
                    .put("owner_uid",kind.getField("ownerUid").getInt(info)).put("unique_id",kind.getField("uniqueId").get(info))
                    .put("owner_package",kind.getField("ownerPackageName").get(info)).put("display_info_read_completed",true)
                    .put("status","READBACK_OBSERVED");
            }catch(Throwable failure){
                Throwable cause=failure;
                while(cause instanceof java.lang.reflect.InvocationTargetException && ((java.lang.reflect.InvocationTargetException)cause).getCause()!=null)
                    cause=((java.lang.reflect.InvocationTargetException)cause).getCause();
                row.put("status","READBACK_ERROR").put("error_stage",stage).put("error_type",cause.getClass().getName())
                    .put("error_message",String.valueOf(cause.getMessage()));
            }
            observations.put(row);
        }
        return new JSONObject().put("schema","hepta.direct-physical-display-access-capability.v1")
            .put("process_uid",android.os.Process.myUid()).put("process_pid",android.os.Process.myPid())
            .put("context_package",shellContext.getPackageName()).put("context_op_package",shellContext.getOpPackageName())
            .put("context_user_id",Context.class.getMethod("getUserId").invoke(shellContext))
            .put("caller_identity_changed",false).put("permission_changes",false).put("observations",observations)
            .put("virtual_display_created",false).put("is_creation_admission_proof",false);
    }

    private static JSONObject displayReadback(DisplayManager dm) throws Exception {
        android.view.Display actual=dm.getDisplay(displayId);
        Object info=displayInfo(actual,displayId),main=displayInfo(dm.getDisplay(0),0),cover=displayInfo(dm.getDisplay(1),1);
        Class<?> kind=Class.forName("android.view.DisplayInfo");
        int group=kind.getField("displayGroupId").getInt(info);
        int mainGroup=kind.getField("displayGroupId").getInt(main),coverGroup=kind.getField("displayGroupId").getInt(cover);
        int owner=kind.getField("ownerUid").getInt(info),uid=android.os.Process.myUid();
        int removeMode=kind.getField("removeMode").getInt(info);
        int destroyMode=android.view.Display.class.getField("REMOVE_MODE_DESTROY_CONTENT").getInt(null);
        Object ownerPackage=kind.getField("ownerPackageName").get(info),unique=kind.getField("uniqueId").get(info);
        if(displayId<=1 || group<=0 || mainGroup<0 || coverGroup<0 || group==mainGroup || group==coverGroup
                || actual.getFlags()!=EXPECTED_DISPLAY_FLAGS || kind.getField("flags").getInt(info)!=EXPECTED_DISPLAY_FLAGS
                || kind.getField("type").getInt(info)!=android.view.Display.class.getField("TYPE_VIRTUAL").getInt(null)
                || owner!=uid || !"com.android.shell".equals(ownerPackage)
                || removeMode!=destroyMode || destroyMode!=1
                || !(unique instanceof String) || ((String)unique).isEmpty()
                || (boundUniqueId!=null && (!boundUniqueId.equals(unique) || boundGroup!=group))
                || !("Hepta public own-group probe-"+generation).equals(actual.getName()))
            throw new SecurityException("protected public display readback differs");
        if(boundUniqueId==null){boundUniqueId=(String)unique;boundGroup=group;}
        return new JSONObject().put("profile",PROFILE).put("requested_flags",FLAGS).put("display_flags",actual.getFlags())
            .put("display_group_id",group).put("physical_main_group_id",mainGroup).put("physical_cover_group_id",coverGroup)
            .put("display_owner_uid",owner).put("display_owner_package",ownerPackage).put("display_unique_id",unique)
            .put("display_name",actual.getName()).put("state",actual.getState()).put("private",false)
            .put("remove_mode",removeMode).put("destroy_content_remove_mode",destroyMode)
            .put("always_unlocked",true).put("capture_secure",false).put("can_show_with_insecure_keyguard",false);
    }

    /** Include disabled logical displays; an incomplete or moving census cannot grant a lease. */
    private static OwnedDisplayPowerLease.Scope powerScope(DisplayManager dm) throws Exception {
        JSONObject verified=displayReadback(dm);
        Object binder=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"display");
        if(!(binder instanceof android.os.IBinder))throw new SecurityException("display service unavailable");
        Object service=Class.forName("android.hardware.display.IDisplayManager$Stub")
            .getMethod("asInterface",android.os.IBinder.class).invoke(null,binder);
        Class<?> api=Class.forName("android.hardware.display.IDisplayManager");
        java.lang.reflect.Method enumerate=api.getMethod("getDisplayIds",boolean.class);
        Object returned=enumerate.invoke(service,true);
        if(!(returned instanceof int[]))throw new SecurityException("complete display IDs unavailable");
        int[] ids=((int[])returned).clone(), groups=new int[ids.length], types=new int[ids.length];
        if(ids.length<3 || ids.length>4096)throw new SecurityException("display census size unavailable");
        Class<?> infoType=Class.forName("android.view.DisplayInfo");
        int ownState=-1;
        for(int i=0;i<ids.length;i++){
            Object info=api.getMethod("getDisplayInfo",int.class).invoke(service,ids[i]);
            if(!infoType.isInstance(info))throw new SecurityException("complete display information unavailable");
            if(infoType.getField("displayId").getInt(info)!=ids[i])
                throw new SecurityException("display identity differs during power census");
            groups[i]=infoType.getField("displayGroupId").getInt(info);
            types[i]=infoType.getField("type").getInt(info);
            if(ids[i]==displayId){
                if(!boundUniqueId.equals(infoType.getField("uniqueId").get(info)) || groups[i]!=boundGroup)
                    throw new SecurityException("owned display changed during power census");
                ownState=infoType.getField("state").getInt(info);
            }
        }
        Object repeated=enumerate.invoke(service,true);
        if(!(repeated instanceof int[]))throw new SecurityException("repeated display IDs unavailable");
        int[] first=ids.clone(),second=((int[])repeated).clone();
        java.util.Arrays.sort(first);java.util.Arrays.sort(second);
        if(!java.util.Arrays.equals(first,second))throw new SecurityException("display census changed during read");
        if(verified.getInt("state")!=ownState)throw new SecurityException("display power readbacks disagree");
        return new OwnedDisplayPowerLease.Scope(displayId,boundGroup,boundUniqueId,ownState,ids,groups,types);
    }

    private static void acquireScreenPower(final DisplayManager dm) throws Exception {
        final Object service=shellContext.getSystemService(Context.POWER_SERVICE);
        if(!(service instanceof PowerManager))throw new SecurityException("power service unavailable");
        final PowerManager power=(PowerManager)service;
        screenPowerTag="HeptaOuterDisplay:"+generation+":"+displayId;
        screenPowerLease=new OwnedDisplayPowerLease(new OwnedDisplayPowerLease.Platform(){
            @Override public OwnedDisplayPowerLease.Scope readScope() throws Exception { return powerScope(dm); }
            @Override public OwnedDisplayPowerLease.ScreenLock newScreenLock(int exactDisplayId) throws Exception {
                if(exactDisplayId<=1 || exactDisplayId!=displayId)throw new SecurityException("owned power display mismatch");
                // No two-argument/global fallback and no wake-up or post-release activity flags.
                Object created=PowerManager.class.getMethod("newWakeLock",int.class,String.class,int.class)
                    .invoke(power,PowerManager.SCREEN_BRIGHT_WAKE_LOCK,screenPowerTag,exactDisplayId);
                if(!(created instanceof PowerManager.WakeLock))throw new SecurityException("display-scoped lock unavailable");
                final PowerManager.WakeLock lock=(PowerManager.WakeLock)created;
                lock.setReferenceCounted(false);
                return new OwnedDisplayPowerLease.ScreenLock(){
                    @Override public void acquire(long timeoutMs){ lock.acquire(timeoutMs); }
                    @Override public boolean isHeld(){ return lock.isHeld(); }
                    @Override public void release(){ lock.release(); }
                };
            }
        },new OwnedDisplayPowerLease.Clock(){
            @Override public long elapsedRealtime(){ return SystemClock.elapsedRealtime(); }
        },displayId,boundGroup,boundUniqueId,deadline);
        startupStage="await_initial_display_on";
        screenPowerLease.awaitInitialOn(initializationDeadline,new OwnedDisplayPowerLease.InitialWait(){
            @Override public void observed(OwnedDisplayPowerLease.Scope actual,long elapsedMs) throws Exception {
                JSONObject sample=new JSONObject().put("observed_elapsed_ms",elapsedMs)
                    .put("display_id",actual.displayId).put("display_group_id",actual.groupId)
                    .put("display_unique_id",actual.uniqueId).put("display_state",actual.state)
                    .put("all_display_ids",new JSONArray(actual.displayIds))
                    .put("all_display_group_ids",new JSONArray(actual.groupIds));
                if(initialPowerObservations.length()>=201)throw new SecurityException("initial power observation bound exceeded");
                initialPowerObservations.put(sample);
                write("initial-screen-power-readiness.json",new JSONObject()
                    .put("schema","hepta.owned-display-initial-power-readiness.v1")
                    .put("pid",android.os.Process.myPid()).put("initialization_deadline_elapsed_ms",initializationDeadline)
                    .put("lifetime_deadline_elapsed_ms",deadline).put("observations",initialPowerObservations)
                    .put("wake_up_calls",0).put("power_api_calls",0));
            }
            @Override public void pause(long millis) throws InterruptedException { Thread.sleep(millis); }
        });
        startupStage="acquire_display_scoped_lock";
        screenPowerLease.acquire();
    }

    private static void writeStartupFailure(Throwable error) {
        try {
            JSONArray causes=new JSONArray();Throwable current=error;
            for(int i=0;current!=null&&i<8;i++){
                causes.put(new JSONObject().put("class",current.getClass().getName())
                    .put("message",current.getMessage()==null?JSONObject.NULL:current.getMessage()));
                if(current.getCause()==current)break;current=current.getCause();
            }
            java.io.StringWriter trace=new java.io.StringWriter();error.printStackTrace(new java.io.PrintWriter(trace));
            write("startup-failure.json",new JSONObject().put("schema","hepta.owned-display-startup-failure.v1")
                .put("pid",android.os.Process.myPid()).put("uid",android.os.Process.myUid())
                .put("stage",startupStage).put("causes",causes).put("stack",trace.toString())
                .put("initialization_deadline_elapsed_ms",initializationDeadline)
                .put("lifetime_deadline_elapsed_ms",deadline).put("initial_power_observations",initialPowerObservations));
        } catch(Throwable diagnosticFailure){ error.addSuppressed(diagnosticFailure); }
    }

    private static JSONObject screenPowerReadback() throws Exception {
        OwnedDisplayPowerLease lease=screenPowerLease;
        if(lease==null)throw new SecurityException("owned screen lease missing");
        lease.requireLive();
        return new JSONObject().put("schema","hepta.owned-display-screen-power-lease.v1")
            .put("display_id",lease.displayId).put("display_group_id",lease.groupId).put("display_unique_id",lease.uniqueId)
            .put("group_members",new JSONArray(lease.groupMembers())).put("wake_lock_level",PowerManager.SCREEN_BRIGHT_WAKE_LOCK)
            .put("wake_lock_tag",screenPowerTag).put("wake_lock_held",lease.isHeld())
            .put("acquired_elapsed_ms",lease.acquiredElapsedMs()).put("requested_timeout_ms",lease.requestedTimeoutMs())
            .put("deadline_elapsed_ms",lease.deadlineElapsedMs).put("display_state",OwnedDisplayPowerLease.STATE_ON)
            .put("wake_up_called",false).put("on_after_release",false).put("default_display_fallback",false);
    }

    private static void requireFlagConstants() throws Exception {
        int flags=0;
        for(String name:new String[]{"VIRTUAL_DISPLAY_FLAG_PUBLIC","VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY",
                "VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH","VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL",
                "VIRTUAL_DISPLAY_FLAG_TRUSTED","VIRTUAL_DISPLAY_FLAG_OWN_DISPLAY_GROUP",
                "VIRTUAL_DISPLAY_FLAG_ALWAYS_UNLOCKED","VIRTUAL_DISPLAY_FLAG_OWN_FOCUS","VIRTUAL_DISPLAY_FLAG_STEAL_TOP_FOCUS_DISABLED"})
            flags|=DisplayManager.class.getField(name).getInt(null);
        int actual=0;
        for(String name:new String[]{"FLAG_TRUSTED","FLAG_OWN_DISPLAY_GROUP","FLAG_ALWAYS_UNLOCKED","FLAG_OWN_FOCUS","FLAG_STEAL_TOP_FOCUS_DISABLED"})
            actual|=android.view.Display.class.getField(name).getInt(null);
        if(flags!=FLAGS || actual!=EXPECTED_DISPLAY_FLAGS)throw new SecurityException("framework flag constants differ");
    }

    private static void stopOwned(String reason,int exitCode) {
        if(!stopping.compareAndSet(false,true))return;
        closeStarted=SystemClock.elapsedRealtime();
        Thread release=new Thread(() -> {
            close(reason);
            // Only this helper is terminated. Process exit is never an absence proof.
            Runtime.getRuntime().halt(exitCode);
        },"HeptaOwnedDisplayRelease");
        release.setDaemon(true);release.start();
    }

    private static void startDeadlineWatchdog() {
        initializationDeadline=SystemClock.elapsedRealtime()+5000;
        Thread watchdog=new Thread(() -> {
            while(true){
                long now=SystemClock.elapsedRealtime();
                if(stopping.get()){
                    if(closeStarted>0 && now-closeStarted>1500)Runtime.getRuntime().halt(70);
                }else if(now>=deadline)stopOwned("owned_display_ttl",0);
                else if(!policyMonitoring){
                    if(now>=initializationDeadline)stopOwned("display_initialization_stalled",70);
                }else if(now-policyHeartbeat>1500)stopOwned("framework_policy_read_stalled",70);
                try{Thread.sleep(50);}catch(InterruptedException interrupted){stopOwned("watchdog_interrupted",70);}
            }
        },"HeptaOwnedDisplayDeadline");
        watchdog.setDaemon(true);watchdog.start();
    }

    private static void startPolicyGuard(final DisplayManager dm) {
        policyHeartbeat=SystemClock.elapsedRealtime();policyMonitoring=true;
        Thread policy=new Thread(() -> {
            while(!stopping.get()){
                try{
                    if(new File(root,"stop").exists()){stopOwned("owned_display_stop",0);return;}
                    JSONObject current=policySnapshot();requireInsecure(current);
                    current.put("display_readback",displayReadback(dm));
                    current.put("screen_power_lease",screenPowerReadback());
                    policyHeartbeat=SystemClock.elapsedRealtime();
                    File request=new File(root,"policy");
                    if(request.exists()){request.delete();write("policy-observation.json",current);}
                    Thread.sleep(250);
                }catch(Throwable changed){
                    // Release starts before diagnostic IO. Unknown state never becomes insecure.
                    stopOwned("protected_display_policy_no_longer_satisfied",70);
                    try{write("policy-rejected.json",new JSONObject().put("error",changed.toString()));}catch(Throwable ignored){}
                    return;
                }
            }
        },"HeptaOwnedDisplayCredentialGuard");
        policy.setDaemon(true);policy.start();
    }


    private static void write(String name, JSONObject value) throws Exception {
        value.put("generation", generation).put("display_id", displayId)
             .put("uptime_ms", SystemClock.uptimeMillis());
        File target = new File(root, name);
        File tmp = new File(root, name + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write((value.toString(2) + "\n").getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        if (!tmp.renameTo(target)) throw new IllegalStateException("receipt rename failed");
    }

    private static void close(String reason) {
        if(!closeClaim.compareAndSet(false,true))return;
        closed=true;
        // Drop the exact screen lease and owned display before AX disconnect or PNG work.
        boolean releaseFailed=false,powerReleaseFailed=false;
        try { if(screenPowerLease!=null)screenPowerLease.close(); } catch(Throwable error) { powerReleaseFailed=true; }
        try { if(display!=null)display.release(); } catch(Throwable error) { releaseFailed=true; }
        synchronized(imageLock){
            try { if(heldImage!=null)heldImage.close(); } catch(Throwable ignored) {}
            heldImage=null;
        }
        try { if(reader!=null)reader.close(); } catch(Throwable ignored) {}
        try { if(observer!=null)UiAutomation.class.getMethod("disconnect").invoke(observer); } catch(Throwable ignored) {}
        try { if(observerThread!=null)observerThread.quitSafely(); } catch(Throwable ignored) {}
        try { write("terminal.json",new JSONObject().put("status","release_requested").put("reason",reason)
            .put("frames",frames).put("release_api_failed",releaseFailed).put("release_verified",false)
            .put("screen_power_lease_release_failed",powerReleaseFailed)
            .put("requires_independent_owned_display_and_task_absence",true)); } catch(Throwable error) { error.printStackTrace(); }
    }


    // Publish non-empty requests atomically as canonical UUID plus newline.
    // Empty touch remains compatible with the earlier host tap helper.
    private static String readCaptureRequest(File request) throws Exception {
        byte[] bytes = new byte[38];
        int length = 0;
        try (FileInputStream in = new FileInputStream(request)) {
            while (length < bytes.length) {
                int count = in.read(bytes, length, bytes.length - length);
                if (count < 0) break;
                length += count;
            }
        }
        if (length == 0) return null;
        if (length != 37 || bytes[36] != '\n')
            throw new IllegalArgumentException("capture request must be canonical UUID plus newline");
        String value = new String(bytes, 0, 36, StandardCharsets.UTF_8);
        try {
            if (!UUID.fromString(value).toString().equals(value))
                throw new IllegalArgumentException();
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("capture request must be canonical UUID plus newline");
        }
        return value;
    }

    private static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        final char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 255;
            out[i * 2] = digits[value >>> 4];
            out[i * 2 + 1] = digits[value & 15];
        }
        return new String(out);
    }

    // Callback and polling share one Handler; the lock also protects shutdown.
    // A static UI can answer a request from the held Image without a new frame.
    private static void captureIfRequested() throws Exception {
        synchronized (imageLock) {
            if (closed || stopping.get() || heldImage == null) return;
            File trigger = new File(root, "capture");
            if (!trigger.exists()) return;
            File request = new File(root, "capture.pending");
            if (!trigger.renameTo(request))
                throw new IllegalStateException("capture request claim failed");
            Bitmap padded = null, exact = null;
            try {
                String requestId = readCaptureRequest(request);
                Image.Plane plane = heldImage.getPlanes()[0];
                if (plane.getPixelStride() != 4 || plane.getRowStride() % 4 != 0)
                    throw new IllegalStateException("unsupported RGBA plane stride");
                int stride = plane.getRowStride() / plane.getPixelStride();
                padded = Bitmap.createBitmap(stride, HEIGHT, Bitmap.Config.ARGB_8888);
                java.nio.ByteBuffer pixels = plane.getBuffer().duplicate();
                pixels.rewind();
                padded.copyPixelsFromBuffer(pixels);
                exact = Bitmap.createBitmap(padded, 0, 0, WIDTH, HEIGHT);
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                File tmp = new File(root, "frame.png.tmp");
                try (FileOutputStream out = new FileOutputStream(tmp)) {
                    DigestOutputStream encoded = new DigestOutputStream(out, digest);
                    if (!exact.compress(Bitmap.CompressFormat.PNG, 100, encoded))
                        throw new IllegalStateException("PNG encoding failed");
                    encoded.flush();
                    out.getFD().sync();
                }
                long pngBytes = tmp.length();
                String pngSha256 = hex(digest.digest());
                if (pngBytes <= 0 || !tmp.renameTo(new File(root, "frame.png")))
                    throw new IllegalStateException("PNG publish failed");
                write("capture.json", new JSONObject()
                    .put("capture_request_id", requestId == null ? JSONObject.NULL : requestId)
                    .put("frames", heldFrame).put("source_uptime_ms", heldSourceUptimeMs)
                    .put("png_sha256", pngSha256).put("png_bytes", pngBytes)
                    .put("width", WIDTH).put("height", HEIGHT));
            } finally {
                if (exact != null && exact != padded) exact.recycle();
                if (padded != null) padded.recycle();
                if (!request.delete() && request.exists())
                    throw new IllegalStateException("capture request cleanup failed");
            }
        }
    }

    private static JSONObject node(AccessibilityNodeInfo n, int depth, int[] count) throws Exception {
        if (stopping.get() || closed || n == null || depth > 24 || ++count[0] > 2000) return null;
        android.graphics.Rect bounds = new android.graphics.Rect();
        n.getBoundsInScreen(bounds);
        JSONObject j = new JSONObject().put("window_id",n.getWindowId())
            .put("package",String.valueOf(n.getPackageName()))
            .put("class",String.valueOf(n.getClassName()))
            .put("id",n.getViewIdResourceName()).put("text",String.valueOf(n.getText()))
            .put("description",String.valueOf(n.getContentDescription()))
            .put("bounds",bounds.flattenToString()).put("clickable",n.isClickable())
            .put("enabled",n.isEnabled()).put("checkable",n.isCheckable())
            .put("checked",n.isChecked()).put("scrollable",n.isScrollable())
            .put("editable",n.isEditable()).put("visible",n.isVisibleToUser());
        JSONArray children = new JSONArray();
        if (!n.isPassword()) for (int i=0; i<n.getChildCount(); ++i) {
            AccessibilityNodeInfo child=n.getChild(i);
            try { JSONObject value=node(child,depth+1,count); if(value!=null) children.put(value); }
            finally { if(child!=null) child.recycle(); }
        }
        if(n.isPassword()) j.put("text","REDACTED").put("description","REDACTED");
        return j.put("children",children);
    }

    private static void observe() throws Exception {
        if(stopping.get() || closed)throw new IllegalStateException("owned display stopping");
        if(observer==null) {
            observerThread=new HandlerThread("HeptaDisplayObserver");
            observerThread.start();
            Class<?> connectionClass=Class.forName("android.app.UiAutomationConnection");
            Object connection=connectionClass.getDeclaredConstructor().newInstance();
            Class<?> connectionInterface=Class.forName("android.app.IUiAutomationConnection");
            Constructor<UiAutomation> ctor=UiAutomation.class.getDeclaredConstructor(Looper.class,connectionInterface);
            ctor.setAccessible(true);
            observer=ctor.newInstance(observerThread.getLooper(),connection);
            UiAutomation.class.getMethod("connect",int.class).invoke(observer,UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            android.accessibilityservice.AccessibilityServiceInfo info=observer.getServiceInfo();
            info.flags |= android.accessibilityservice.AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
                       | android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
            observer.setServiceInfo(info);
        }
        if(stopping.get() || closed)throw new IllegalStateException("owned display stopping");
        SparseArray<List<AccessibilityWindowInfo>> all=observer.getWindowsOnAllDisplays();
        JSONArray windows=new JSONArray();
        List<AccessibilityWindowInfo> target=all.get(displayId);
        if(target!=null) for(AccessibilityWindowInfo w:target) {
            JSONObject item=new JSONObject().put("id",w.getId()).put("display_id",w.getDisplayId())
                .put("active",w.isActive()).put("focused",w.isFocused()).put("title",String.valueOf(w.getTitle()));
            AccessibilityNodeInfo n=w.getRoot();
            try { item.put("root",node(n,0,new int[1])); } finally {if(n!=null)n.recycle();}
            windows.put(item);
        }
        write("observation.json",new JSONObject().put("windows",windows)
            .put("non_suppressing",true).put("frames",frames));
    }

    public static void main(String[] args) throws Exception {
        if((args.length!=1 && args.length!=2) || !args[0].matches("/data/local/tmp/hepta-vdisplay-[a-zA-Z0-9-]+")
            || (args.length==2 && !"--capabilities-only".equals(args[1])))
            throw new IllegalArgumentException("unique private probe directory required");
        root=new File(args[0]);
        if(!root.isDirectory())throw new IllegalArgumentException("directory missing");
        generation=UUID.randomUUID().toString();
        Looper.prepareMainLooper();
        handler=new Handler(Looper.getMainLooper());
        Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
        Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
        Context shell=system.createPackageContext("com.android.shell",0);
        shellContext=shell;
        requireFlagConstants();
        JSONObject policyBefore=policySnapshot();
        write("policy-preflight.json",policyBefore);
        if(args.length==2) {
            DisplayManager capabilityDisplays=(DisplayManager)shell.getSystemService(Context.DISPLAY_SERVICE);
            JSONObject physicalAccess=physicalDisplayAccess(capabilityDisplays);
            write("physical-display-access.json",physicalAccess);
            JSONObject directAccess=directPhysicalDisplayAccess();
            write("direct-physical-display-access.json",directAccess);
            write("capabilities.json",new JSONObject(policyBefore.toString()).put("capabilities_only",true)
                .put("physical_display_access",physicalAccess).put("direct_physical_display_access",directAccess)
                .put("display_created",false).put("accessibility_connected",false).put("ui_input",false));
            System.out.println("capabilities_only_complete"); System.exit(0); return;
        }
        requireInsecure(policyBefore);
        DisplayManager dm=(DisplayManager)shell.getSystemService(Context.DISPLAY_SERVICE);
        reader=ImageReader.newInstance(WIDTH,HEIGHT,PixelFormat.RGBA_8888,3);
        reader.setOnImageAvailableListener(r -> {
            try {
                synchronized (imageLock) {
                    if (closed) return;
                    Image next = r.acquireLatestImage();
                    if (next != null) {
                        Image previous = heldImage;
                        heldImage = next;
                        heldFrame = ++frames;
                        heldSourceUptimeMs = SystemClock.uptimeMillis();
                        if (previous != null) previous.close();
                    }
                }
                captureIfRequested();
            } catch(Throwable error){error.printStackTrace();}
        },handler);
        deadline=SystemClock.elapsedRealtime()+900000L;
        startDeadlineWatchdog();
        try {
        display=dm.createVirtualDisplay("Hepta public own-group probe-"+generation,WIDTH,HEIGHT,240,reader.getSurface(),FLAGS);
        if(display==null)throw new IllegalStateException("virtual display unavailable");
        displayId=display.getDisplay().getDisplayId();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> close("process_shutdown")));
        startupStage="initial_display_readback";
        JSONObject displayBefore=displayReadback(dm);
        acquireScreenPower(dm);
        startupStage="held_screen_power_readback";
        JSONObject powerBefore=screenPowerReadback();
        displayBefore=displayReadback(dm);
        write("screen-power-lease.json",powerBefore);
        write("display-policy-readback.json",displayBefore);
        requireInsecure(policySnapshot());
        startupStage="configure_owned_ime";
        Object wm=Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
        Class.forName("android.view.IWindowManager").getMethod("setDisplayImePolicy",int.class,int.class).invoke(wm,displayId,2);
        Object ime=Class.forName("android.view.IWindowManager").getMethod("getDisplayImePolicy",int.class).invoke(wm,displayId);
        if(!(ime instanceof Integer) || ((Integer)ime).intValue()!=2)throw new SecurityException("IME hide policy unavailable");
        startupStage="publish_created";
        write("created.json",new JSONObject().put("status","created").put("uid",android.os.Process.myUid())
            .put("pid",android.os.Process.myPid()).put("requested_flags",FLAGS)
            .put("display_flags",display.getDisplay().getFlags()).put("ime_policy","hide")
            .put("ttl_ms",900000).put("capture_secure",false).put("always_unlocked",true)
            .put("profile",PROFILE).put("display_group_id",displayBefore.getInt("display_group_id"))
            .put("display_name",display.getDisplay().getName()).put("display_readback",displayBefore).put("policy_before",policyBefore)
            .put("screen_power_lease",powerBefore));
        startPolicyGuard(dm);
        startupStage="running";
        handler.post(new Runnable() { public void run() {
            try {
                if(stopping.get() || closed)return;
                captureIfRequested();
                File request=new File(root,"observe");
                if(request.exists()) {
                    request.delete();
                    try { observe(); } catch(Throwable error) {
                        write("observation-error.json",new JSONObject().put("error",error.toString()));
                    }
                }
            } catch(Throwable error){error.printStackTrace();}
            handler.postDelayed(this,250);
        }});
        Looper.loop();
        } catch(Exception | Error failure) { writeStartupFailure(failure); throw failure;
        } finally { close("main_exit"); }
    }
}
