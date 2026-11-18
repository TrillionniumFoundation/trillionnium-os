package org.trillionnium.hepta.background;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.IBinder;
import android.os.SystemClock;
import android.view.Display;
import android.view.WindowManager;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read-only, actual framework evidence for the explicitly versioned root-owned scope.
 * No credential, global keyguard, user, physical power, focus or task mutation API exists here. */
final class PublicOwnGroupFramework {
    private final Context shell;
    private final DisplayManager displays;
    private final PublicOwnGroupPolicy.Scope scope;
    private final Object windows,trust,activities;
    private final Method keyguardLocked,keyguardSecure,deviceSecure,deviceLocked,currentUser,getIme,getDisplayInfo;
    private final Class<?> infoType;
    final int requestedFlags,actualFlags,imeHide,destroyMode;
    private Map<Integer,String> physicalBaseline;
    private PublicOwnGroupPolicy.Readback first;

    PublicOwnGroupFramework(Context shell,DisplayManager displays,PublicOwnGroupPolicy.Scope scope,
            ProfileRecoveryBootCount bootCount,long initializationDeadline)throws Exception{
        this.shell=shell;this.displays=displays;this.scope=scope;
        need(shell!=null&&displays!=null&&scope!=null&&android.os.Process.myUid()==0,"PUBLIC_SCOPE_ROOT_REQUIRED");
        need(android.os.Build.VERSION.SDK_INT==36,"PUBLIC_SCOPE_PLATFORM_UNSUPPORTED");
        need(integer(Context.class.getMethod("getUserId").invoke(shell))==0,"PUBLIC_SCOPE_CONTEXT_USER_INVALID");
        // A standalone root app_process has no registered IApplicationThread for ContentResolver.
        // Read the real SettingsService value through the same owned command used by recovery.
        PublicOwnGroupBootIdentity.requireCurrent(bootCount,scope.bootCount,
                SystemClock.elapsedRealtime(),initializationDeadline);
        windows=Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
        activities=Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
        Object binder=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"trust");
        need(binder instanceof IBinder&&windows!=null&&activities!=null,"PUBLIC_SCOPE_SERVICES_UNAVAILABLE");
        trust=Class.forName("android.app.trust.ITrustManager$Stub").getMethod("asInterface",IBinder.class).invoke(null,binder);
        need(trust!=null,"PUBLIC_SCOPE_SERVICES_UNAVAILABLE");
        Class<?> wm=Class.forName("android.view.IWindowManager"),tm=Class.forName("android.app.trust.ITrustManager");
        keyguardLocked=wm.getMethod("isKeyguardLocked");keyguardSecure=wm.getMethod("isKeyguardSecure",int.class);
        deviceSecure=tm.getMethod("isDeviceSecure",int.class,int.class);deviceLocked=tm.getMethod("isDeviceLocked",int.class,int.class);
        currentUser=Class.forName("android.app.IActivityManager").getMethod("getCurrentUserId");
        getIme=wm.getMethod("getDisplayImePolicy",int.class);
        infoType=Class.forName("android.view.DisplayInfo");getDisplayInfo=Display.class.getMethod("getDisplayInfo",infoType);
        requestedFlags=bits(DisplayManager.class,"VIRTUAL_DISPLAY_FLAG_PUBLIC","VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY",
                "VIRTUAL_DISPLAY_FLAG_SUPPORTS_TOUCH","VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL","VIRTUAL_DISPLAY_FLAG_TRUSTED",
                "VIRTUAL_DISPLAY_FLAG_OWN_DISPLAY_GROUP","VIRTUAL_DISPLAY_FLAG_ALWAYS_UNLOCKED","VIRTUAL_DISPLAY_FLAG_OWN_FOCUS",
                "VIRTUAL_DISPLAY_FLAG_STEAL_TOP_FOCUS_DISABLED");
        actualFlags=bits(Display.class,"FLAG_TRUSTED","FLAG_OWN_DISPLAY_GROUP","FLAG_ALWAYS_UNLOCKED","FLAG_OWN_FOCUS","FLAG_STEAL_TOP_FOCUS_DISABLED");
        imeHide=WindowManager.class.getField("DISPLAY_IME_POLICY_HIDE").getInt(null);
        destroyMode=Display.class.getField("REMOVE_MODE_DESTROY_CONTENT").getInt(null);
        need(requestedFlags==PublicOwnGroupPolicy.REQUESTED_FLAGS&&actualFlags==PublicOwnGroupPolicy.ACTUAL_FLAGS
                &&destroyMode==PublicOwnGroupPolicy.DESTROY_CONTENT&&imeHide==2,"PUBLIC_SCOPE_CONSTANTS_UNSUPPORTED");
        preflight();
    }
    private static void need(boolean value,String code)throws BrokerProtocol.Refusal{if(!value)throw new BrokerProtocol.Refusal(code);}
    private static int integer(Object value)throws BrokerProtocol.Refusal{need(value instanceof Integer,"PUBLIC_SCOPE_INTEGER_UNKNOWN");return ((Integer)value).intValue();}
    private static boolean bool(Object value)throws BrokerProtocol.Refusal{need(value instanceof Boolean,"PUBLIC_SCOPE_BOOLEAN_UNKNOWN");return ((Boolean)value).booleanValue();}
    private static int bits(Class<?> type,String... names)throws Exception{int mask=0;for(String name:names){int bit=type.getField(name).getInt(null);
        need(bit>0&&(bit&(bit-1))==0&&(mask&bit)==0,"PUBLIC_SCOPE_CONSTANTS_UNSUPPORTED");mask|=bit;}return mask;}
    private int field(Object info,String name)throws Exception{return infoType.getField(name).getInt(info);}
    private String text(Object info,String name)throws Exception{Object value=infoType.getField(name).get(info);
        need(value instanceof String&&!((String)value).isEmpty(),"PUBLIC_SCOPE_DISPLAY_INFORMATION_UNKNOWN");return (String)value;}
    private Object info(Display display)throws Exception{
        need(display!=null&&display.isValid(),"PUBLIC_SCOPE_DISPLAY_INFORMATION_UNKNOWN");Object value=infoType.getDeclaredConstructor().newInstance();
        need(bool(getDisplayInfo.invoke(display,value)),"PUBLIC_SCOPE_DISPLAY_INFORMATION_UNKNOWN");return value;
    }
    private PublicOwnGroupPolicy.Privileges privileges(){int uid=android.os.Process.myUid(),pid=android.os.Process.myPid();
        return new PublicOwnGroupPolicy.Privileges(uid,shell.checkPermission("android.permission.ADD_TRUSTED_DISPLAY",pid,uid),
                shell.checkPermission("android.permission.ADD_ALWAYS_UNLOCKED_DISPLAY",pid,uid),
                shell.checkPermission("android.permission.INTERNAL_SYSTEM_WINDOW",pid,uid));}
    private PublicOwnGroupPolicy.UserState user(int id)throws Exception{
        // Device 0 is the physical/default credential domain, not this virtual display's id.
        return new PublicOwnGroupPolicy.UserState(id,0,bool(keyguardSecure.invoke(windows,id)),
                bool(deviceSecure.invoke(trust,id,0)),bool(deviceLocked.invoke(trust,id,0)));
    }
    private PublicOwnGroupPolicy.Credentials credentials()throws Exception{
        int before=integer(currentUser.invoke(activities));boolean locked=bool(keyguardLocked.invoke(windows));
        PublicOwnGroupPolicy.UserState owner=user(0),target=scope.targetUserId==0?owner:user(scope.targetUserId);
        need(before==integer(currentUser.invoke(activities)),"PUBLIC_SCOPE_CURRENT_USER_CHANGED_DURING_READ");
        return new PublicOwnGroupPolicy.Credentials(before,locked,owner,target);
    }
    /** Stable DisplayInfo device identities plus separate mutable physical observations.
     * Neither component is a task, focus-window or recents absence proof. */
    private PublicOwnGroupPolicy.PhysicalDisplays physicalIdentities()throws Exception{
        Map<Integer,String> result=new LinkedHashMap<Integer,String>(),facts=new LinkedHashMap<Integer,String>();
        java.util.Set<String> uniqueIds=new java.util.HashSet<String>();Display[] all=displays.getDisplays();
        need(all!=null&&all.length>=2&&all.length<=32,"PUBLIC_SCOPE_PHYSICAL_CENSUS_UNKNOWN");
        for(Display value:all){Object actual=info(value);int id=value.getDisplayId(),type=field(actual,"type");
            if(id!=0&&id!=1){need(type==5,"PUBLIC_SCOPE_UNREVIEWED_PHYSICAL_DISPLAY");continue;}
            String unique=text(actual,"uniqueId");need(type==1&&unique.matches("local:[0-9]+")&&uniqueIds.add(unique),
                    "PUBLIC_SCOPE_PHYSICAL_IDENTITY_UNKNOWN");
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF("hepta.public-own-group.physical-device-identity.v1");out.writeInt(id);out.writeUTF(unique);out.writeInt(type);
            out.flush();need(result.put(id,ProfileIdentity.sha(bytes.toByteArray()))==null,"PUBLIC_SCOPE_PHYSICAL_IDENTITY_UNKNOWN");
            facts.put(id,new org.json.JSONObject().put("source","android.view.DisplayInfo").put("display_id",id).put("unique_id",unique)
                    .put("type",type).put("group",field(actual,"displayGroupId")).put("state",value.getState()).put("rotation",value.getRotation())
                    .put("width",field(actual,"logicalWidth")).put("height",field(actual,"logicalHeight"))
                    .put("density",field(actual,"logicalDensityDpi")).put("controls_runtime_admission",false).toString());
        }
        need(result.size()==2&&result.containsKey(0)&&result.containsKey(1),"PUBLIC_SCOPE_PHYSICAL_CENSUS_UNKNOWN");
        return new PublicOwnGroupPolicy.PhysicalDisplays(result,facts);
    }
    private synchronized void freeze(PublicOwnGroupPolicy.PhysicalDisplays physical)throws Exception{
        if(physicalBaseline==null)physicalBaseline=physical.stableDeviceIdentities;
        else need(physicalBaseline.equals(physical.stableDeviceIdentities),"PUBLIC_SCOPE_PHYSICAL_DEVICE_CHANGED");
    }
    void preflight()throws Exception{
        PublicOwnGroupPolicy.PhysicalDisplays before=physicalIdentities();privileges();PublicOwnGroupPolicy.Credentials locks=credentials();
        PublicOwnGroupPolicy.PhysicalDisplays after=physicalIdentities();PublicOwnGroupPolicy.Credentials ending=credentials();
        need(locks.currentUserId==ending.currentUserId,"PUBLIC_SCOPE_CURRENT_USER_CHANGED_DURING_READ");
        need(before.stableDeviceIdentities.equals(after.stableDeviceIdentities),"PUBLIC_SCOPE_PHYSICAL_DEVICE_CHANGED_DURING_READ");freeze(after);
    }
    private PublicOwnGroupPolicy.DisplayState display(int id,String expectedName)throws Exception{
        Display actual=displays.getDisplay(id);Object value=info(actual),main=info(displays.getDisplay(0)),cover=info(displays.getDisplay(1));
        need(expectedName.equals(actual.getName())&&field(value,"type")==5&&field(value,"flags")==actual.getFlags(),"PUBLIC_SCOPE_DISPLAY_IDENTITY_CHANGED");
        return new PublicOwnGroupPolicy.DisplayState(id,actual.getName(),text(value,"uniqueId"),field(value,"ownerUid"),text(value,"ownerPackageName"),
                actual.getFlags(),field(value,"displayGroupId"),field(main,"displayGroupId"),field(cover,"displayGroupId"),
                field(value,"removeMode"),destroyMode,integer(getIme.invoke(windows,id)),imeHide);
    }
    PublicOwnGroupPolicy.Readback read(String requestId,int displayId,String displayName)throws Exception{
        long begin=SystemClock.elapsedRealtime();PublicOwnGroupPolicy.PhysicalDisplays before=physicalIdentities();
        PublicOwnGroupPolicy.Privileges allowed=privileges();PublicOwnGroupPolicy.Credentials locks=credentials();
        PublicOwnGroupPolicy.DisplayState state=display(displayId,displayName);PublicOwnGroupPolicy.PhysicalDisplays after=physicalIdentities();
        PublicOwnGroupPolicy.Credentials ending=credentials();
        need(locks.currentUserId==ending.currentUserId,"PUBLIC_SCOPE_CURRENT_USER_CHANGED_DURING_READ");
        need(before.stableDeviceIdentities.equals(after.stableDeviceIdentities),"PUBLIC_SCOPE_PHYSICAL_DEVICE_CHANGED_DURING_READ");freeze(after);
        PublicOwnGroupPolicy.Readback value=new PublicOwnGroupPolicy.Readback(scope,requestId,begin,SystemClock.elapsedRealtime(),allowed,ending,state,after);
        synchronized(this){need(first==null||first.sameLifetimeIdentity(value),"PUBLIC_SCOPE_DISPLAY_LIFETIME_IDENTITY_CHANGED");if(first==null)first=value;}
        return value;
    }
    synchronized boolean hasFrozenIdentity(){return first!=null;}
    /** Frozen, actual framework facts only. During shutdown the broker separately checks
     * its exact create-returned VD object. A new DisplayInfo query is deliberately not
     * a shutdown dependency: a reused integer id never replaces that Binder-owning object. */
    synchronized boolean frozenIdentityMatches(int id,String name){
        if(first==null)return false;PublicOwnGroupPolicy.DisplayState original=first.display;
        return id==original.displayId&&name.equals(original.name)&&original.ownerUid==0
                &&"com.android.shell".equals(original.ownerPackage)&&original.flags==PublicOwnGroupPolicy.ACTUAL_FLAGS
                &&original.groupId>0&&original.removeMode==1&&original.destroyConstant==1;
    }
}
