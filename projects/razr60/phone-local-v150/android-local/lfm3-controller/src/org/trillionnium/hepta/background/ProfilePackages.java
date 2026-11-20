package org.trillionnium.hepta.background;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.SystemClock;
import android.os.UserHandle;
import android.os.UserManager;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Root broker's read-only per-user PM adapter. No user creation, policy changes or app data reads. */
final class ProfilePackages {
    static final class Readback {
        final ProfileTarget target;
        final ProfileTaskPolicy.Activity activity;
        final boolean running,unlocked,quiet,suspended;
        Readback(ProfileTarget target,ProfileTaskPolicy.Activity activity,boolean running,boolean unlocked,
                 boolean quiet,boolean suspended){this.target=target;this.activity=activity;this.running=running;
            this.unlocked=unlocked;this.quiet=quiet;this.suspended=suspended;}
    }
    private final Context shell;
    private final UserManager users;
    private final Map<String,CachedApk> hashedApks=new java.util.HashMap<String,CachedApk>();
    private static final class CachedApk {
        final String stat,digest;
        CachedApk(String stat,String digest){this.stat=stat;this.digest=digest;}
    }
    ProfilePackages(Context shell)throws Exception{
        need(android.os.Process.myUid()==0,"PROFILE_ROOT_BROKER_REQUIRED");
        need(android.os.Build.VERSION.SDK_INT==36,"PROFILE_PLATFORM_VERSION_UNSUPPORTED");
        this.shell=shell;users=(UserManager)shell.getSystemService(Context.USER_SERVICE);
        need(users!=null,"PROFILE_USER_SERVICE_UNAVAILABLE");
    }
    List<Integer> selectableUsers()throws Exception{
        requireParentCurrent();
        Object raw=UserManager.class.getMethod("getProfiles",int.class).invoke(users,0);
        need(raw instanceof List&&((List<?>)raw).size()<=16,"PROFILE_CATALOGUE_INCOMPLETE");
        Set<Integer> unique=new TreeSet<Integer>();List<Integer> result=new ArrayList<Integer>();
        for(Object info:(List<?>)raw){
            need(info!=null,"PROFILE_CATALOGUE_INCOMPLETE");int id=integer(info,"id");
            need(id>=0&&unique.add(id),"PROFILE_CATALOGUE_DUPLICATE");
            Object managed=info.getClass().getMethod("isManagedProfile").invoke(info);
            need(managed instanceof Boolean,"PROFILE_USER_TYPE_UNKNOWN");
            if(Boolean.TRUE.equals(managed))result.add(id);
        }
        need(unique.contains(0),"PROFILE_PARENT_MISSING");return result;
    }
    Readback read(int userId,String packageName,boolean requireReady,long deadline)throws Exception{
        need(ProfileTarget.supportsPackage(packageName),"PROFILE_PACKAGE_NOT_SUPPORTED");
        checkTime(deadline);requireParentCurrent();
        ProfileIdentity identity=identity(userId);
        UserHandle handle=handle(userId);
        boolean running=userState("isUserRunning",handle),unlocked=userState("isUserUnlocked",handle),quiet=users.isQuietModeEnabled(handle);
        if(requireReady)need(running&&unlocked&&!quiet,"PROFILE_NOT_RUNNING_UNLOCKED");
        Context userContext=(Context)Context.class.getMethod("createContextAsUser",UserHandle.class,int.class)
                .invoke(shell,handle,0);
        Object contextUser=Context.class.getMethod("getUserId").invoke(userContext);
        need(contextUser instanceof Integer&&((Integer)contextUser)==userId,"PROFILE_CONTEXT_USER_MISMATCH");
        PackageManager pm=userContext.getPackageManager();
        PackageInfo before=pm.getPackageInfo(packageName,PackageManager.GET_SIGNING_CERTIFICATES);
        ApplicationInfo app=before.applicationInfo;
        need(app!=null&&packageName.equals(before.packageName)&&packageName.equals(app.packageName)
                &&app.uid>0&&app.uid/100000==userId&&(app.flags&ApplicationInfo.FLAG_INSTALLED)!=0,
                "PROFILE_INSTALLATION_NOT_PRESENT");
        boolean suspended=pm.isPackageSuspended(packageName);
        if(requireReady)need(app.enabled&&!suspended&&!pm.isInstantApp(packageName),"PROFILE_PACKAGE_UNAVAILABLE");
        Intent launcher=pm.getLaunchIntentForPackage(packageName);
        need(launcher!=null&&launcher.getComponent()!=null
                &&packageName.equals(launcher.getComponent().getPackageName()),"PROFILE_LAUNCHER_UNAVAILABLE");
        ComponentName launcherComponent=launcher.getComponent();
        Intent home=ProfileTarget.XIAOMI.equals(packageName)?BackgroundTaskOrganizer.nativeHome(userContext,launcher):null;
        if(ProfileTarget.XIAOMI.equals(packageName))need(home!=null,"PROFILE_NATIVE_HOME_UNAVAILABLE");
        ComponentName component=home==null?launcherComponent:home.getComponent();
        ActivityInfo activity=pm.getActivityInfo(component,0);
        need(activity.applicationInfo!=null&&activity.applicationInfo.uid==app.uid
                &&Objects.equals(activity.applicationInfo.sourceDir,app.sourceDir),"PROFILE_ACTIVITY_UID_MISMATCH");
        Map<String,String> paths=paths(app);Map<String,String> hashes=new TreeMap<String,String>();
        for(Map.Entry<String,String> row:paths.entrySet()){checkTime(deadline);hashes.put(row.getKey(),hashApk(row.getValue(),deadline));}
        Set<String> signers=signers(before);
        PackageInfo after=pm.getPackageInfo(packageName,PackageManager.GET_SIGNING_CERTIFICATES);
        need(after.applicationInfo!=null&&after.applicationInfo.uid==app.uid&&after.getLongVersionCode()==before.getLongVersionCode()
                &&after.lastUpdateTime==before.lastUpdateTime&&after.firstInstallTime==before.firstInstallTime
                &&paths.equals(paths(after.applicationInfo))&&signers.equals(signers(after))
                &&after.applicationInfo.enabled==app.enabled&&pm.isPackageSuspended(packageName)==suspended,
                "PROFILE_INSTALLATION_CHANGED_DURING_READ");
        ProfileIdentity finalIdentity=identity(userId);
        need(identity.same(finalIdentity)&&running==userState("isUserRunning",handle)&&unlocked==userState("isUserUnlocked",handle)
                &&quiet==users.isQuietModeEnabled(handle),"PROFILE_STATE_CHANGED_DURING_READ");
        ProfileTarget actual=new ProfileTarget(identity,app.uid,packageName,
                component.getPackageName()+"/"+component.getClassName(),before.getLongVersionCode(),hashes,signers);
        int forbidden=0;
        for(String name:new String[]{"FLAG_ALLOW_TASK_REPARENTING","FLAG_RELINQUISH_TASK_IDENTITY","FLAG_SHOW_FOR_ALL_USERS"}){
            int bit=ActivityInfo.class.getField(name).getInt(null);
            need(bit>0&&(bit&(bit-1))==0&&(forbidden&bit)==0,"PROFILE_ACTIVITY_FLAGS_UNAVAILABLE");forbidden|=bit;
        }
        ProfileTaskPolicy.Activity facts=new ProfileTaskPolicy.Activity(activity.packageName,
                activity.packageName+"/"+activity.name,activity.applicationInfo.uid,activity.launchMode,
                activity.documentLaunchMode,activity.flags,forbidden,activity.enabled,activity.applicationInfo.enabled,
                activity.exported,activity.targetActivity,activity.permission,activity.applicationInfo.sourceDir,activity.taskAffinity);
        if(requireReady)facts.requireEligible(actual);
        Intent finalLauncher=pm.getLaunchIntentForPackage(packageName);
        need(finalLauncher!=null&&launcherComponent.equals(finalLauncher.getComponent()),"PROFILE_LAUNCHER_CHANGED_DURING_READ");
        if(ProfileTarget.XIAOMI.equals(packageName)){
            Intent finalHome=BackgroundTaskOrganizer.nativeHome(userContext,finalLauncher);
            need(finalHome!=null&&component.equals(finalHome.getComponent()),"PROFILE_NATIVE_HOME_CHANGED_DURING_READ");
        }
        ActivityInfo checked=pm.getActivityInfo(component,0);
        need(checked.applicationInfo!=null,"PROFILE_ACTIVITY_CHANGED_DURING_READ");
        ProfileTaskPolicy.Activity finalFacts=new ProfileTaskPolicy.Activity(checked.packageName,
                checked.packageName+"/"+checked.name,checked.applicationInfo.uid,checked.launchMode,
                checked.documentLaunchMode,checked.flags,forbidden,checked.enabled,checked.applicationInfo.enabled,
                checked.exported,checked.targetActivity,checked.permission,checked.applicationInfo.sourceDir,checked.taskAffinity);
        need(facts.same(finalFacts),"PROFILE_ACTIVITY_CHANGED_DURING_READ");
        checkTime(deadline);return new Readback(actual,facts,running,unlocked,quiet,suspended);
    }
    /** No caller-provided action/extras. The actual target-user PM read binds this component. */
    static Intent launchIntent(ProfileTarget target)throws Exception{
        need(target!=null&&ProfileTarget.supportsPackage(target.packageName),"PROFILE_PACKAGE_NOT_SUPPORTED");
        ComponentName component=ComponentName.unflattenFromString(target.component);
        need(component!=null,"PROFILE_LAUNCHER_UNAVAILABLE");
        boolean home=ProfileTarget.XIAOMI.equals(target.packageName);
        if(home)need(BackgroundOwnedSingleTask.COMPONENT.equals(target.component),"PROFILE_NATIVE_HOME_COMPONENT_INVALID");
        Intent intent=new Intent(home?BackgroundOwnedSingleTask.ACTION:Intent.ACTION_MAIN)
                .setComponent(component).setPackage(target.packageName)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
        if(!home)intent.addCategory(Intent.CATEGORY_LAUNCHER);
        return intent;
    }
    ProfilePermissionTransient.Authority permissionController(int userId,long deadline)throws Exception{
        checkTime(deadline);requireParentCurrent();ProfileIdentity profile=identity(userId);
        Context context=(Context)Context.class.getMethod("createContextAsUser",UserHandle.class,int.class)
                .invoke(shell,handle(userId),0);
        need(Integer.valueOf(userId).equals(Context.class.getMethod("getUserId").invoke(context)),
                "PROFILE_PERMISSION_CONTEXT_USER_MISMATCH");
        PackageManager pm=context.getPackageManager();
        String configured=(String)PackageManager.class.getMethod("getPermissionControllerPackageName").invoke(pm);
        need(ProfilePermissionTransient.PACKAGE.equals(configured),"PROFILE_PERMISSION_SYSTEM_PACKAGE_MISMATCH");
        PackageInfo before=pm.getPackageInfo(configured,PackageManager.GET_SIGNING_CERTIFICATES);
        ApplicationInfo app=before.applicationInfo;
        need(app!=null&&configured.equals(before.packageName)&&configured.equals(app.packageName)
                &&app.uid/100000==userId,"PROFILE_PERMISSION_PACKAGE_USER_MISMATCH");
        Map<String,String> apkPaths=paths(app);
        need(apkPaths.equals(java.util.Collections.singletonMap("base",ProfilePermissionTransient.APK)),
                "PROFILE_PERMISSION_APK_SET_CHANGED");
        int bit=ApplicationInfo.class.getField("PRIVATE_FLAG_PRIVILEGED").getInt(null);
        need(bit>0&&(bit&(bit-1))==0,"PROFILE_PERMISSION_PRIVILEGED_FLAG_UNKNOWN");
        int privateFlags=ApplicationInfo.class.getField("privateFlags").getInt(app);
        ComponentName component=ComponentName.unflattenFromString(ProfilePermissionTransient.COMPONENT);
        ActivityInfo activity=pm.getActivityInfo(component,0);
        need(activity!=null&&activity.applicationInfo!=null&&configured.equals(activity.packageName)
                &&component.getClassName().equals(activity.name)&&activity.applicationInfo.uid==app.uid
                &&Objects.equals(activity.applicationInfo.sourceDir,app.sourceDir),"PROFILE_PERMISSION_ACTIVITY_PM_MISMATCH");
        Set<String> certificates=signers(before);need(certificates.size()==1,"PROFILE_PERMISSION_SIGNER_SET_CHANGED");
        boolean available=app.enabled&&activity.enabled&&!pm.isPackageSuspended(configured)&&!pm.isInstantApp(configured);
        ProfilePermissionTransient.Authority authority=new ProfilePermissionTransient.Authority(userId,app.uid,configured,
                app.sourceDir,hashApk(app.sourceDir,deadline),certificates.iterator().next(),before.getLongVersionCode(),
                (app.flags&ApplicationInfo.FLAG_SYSTEM)!=0,(privateFlags&bit)!=0,
                (app.flags&ApplicationInfo.FLAG_INSTALLED)!=0,available);
        PackageInfo after=pm.getPackageInfo(configured,PackageManager.GET_SIGNING_CERTIFICATES);
        ActivityInfo afterActivity=pm.getActivityInfo(component,0);
        need(after.applicationInfo!=null&&afterActivity.applicationInfo!=null
                &&after.applicationInfo.uid==app.uid&&after.applicationInfo.flags==app.flags
                &&ApplicationInfo.class.getField("privateFlags").getInt(after.applicationInfo)==privateFlags
                &&after.applicationInfo.enabled==app.enabled&&after.getLongVersionCode()==before.getLongVersionCode()
                &&after.lastUpdateTime==before.lastUpdateTime&&after.firstInstallTime==before.firstInstallTime
                &&paths(after.applicationInfo).equals(apkPaths)&&signers(after).equals(certificates)
                &&afterActivity.enabled==activity.enabled&&Objects.equals(afterActivity.name,activity.name)
                &&Objects.equals(afterActivity.packageName,activity.packageName)&&afterActivity.applicationInfo.uid==app.uid
                &&Objects.equals(afterActivity.applicationInfo.sourceDir,app.sourceDir)
                &&configured.equals(PackageManager.class.getMethod("getPermissionControllerPackageName").invoke(pm))
                &&!pm.isPackageSuspended(configured)&&!pm.isInstantApp(configured)&&profile.same(identity(userId)),
                "PROFILE_PERMISSION_SYSTEM_IDENTITY_CHANGED_DURING_READ");
        checkTime(deadline);return authority;
    }
    ProfileIdentity identity(int userId)throws Exception{
        need(userId>0,"PROFILE_USER_ZERO_FORBIDDEN");
        Object info=UserManager.class.getMethod("getUserInfo",int.class).invoke(users,userId);
        need(info!=null&&integer(info,"id")==userId,"PROFILE_USER_MISSING");
        need(Boolean.TRUE.equals(info.getClass().getMethod("isManagedProfile").invoke(info))
                &&Boolean.TRUE.equals(info.getClass().getMethod("isEnabled").invoke(info))
                &&!bool(info,"partial")&&!bool(info,"preCreated"),"PROFILE_USER_NOT_ELIGIBLE");
        Object parent=UserManager.class.getMethod("getProfileParent",int.class).invoke(users,userId);
        need(parent!=null&&integer(parent,"id")==0,"PROFILE_PARENT_MISMATCH");
        Object type=info.getClass().getField("userType").get(info);
        need(type instanceof String,"PROFILE_TYPE_UNKNOWN");
        long serial=users.getSerialNumberForUser(handle(userId));
        return new ProfileIdentity(userId,serial,integer(parent,"id"),(String)type);
    }
    private void requireParentCurrent()throws Exception{
        Object current=ActivityManager.class.getMethod("getCurrentUser").invoke(null);
        need(current instanceof Integer&&((Integer)current)==0,"PROFILE_PARENT_NOT_CURRENT");
    }
    private static Map<String,String> paths(ApplicationInfo app)throws Exception{
        need(app!=null,"PROFILE_APK_PATHS_UNKNOWN");Map<String,String> result=new TreeMap<String,String>();
        addPath(result,"base",app.sourceDir);
        String[] sources=app.splitSourceDirs;
        Object rawNames=ApplicationInfo.class.getField("splitNames").get(app);
        need(rawNames==null||rawNames instanceof String[],"PROFILE_SPLIT_SET_INCOMPLETE");
        String[] names=(String[])rawNames;
        need((sources==null)==(names==null),"PROFILE_SPLIT_SET_INCOMPLETE");
        if(sources!=null){
            need(sources.length==names.length&&sources.length<=31,"PROFILE_SPLIT_SET_INCOMPLETE");
            for(int i=0;i<sources.length;i++){
                need(names[i]!=null&&names[i].matches("[A-Za-z0-9_.-]{1,128}"),"PROFILE_SPLIT_NAME_INVALID");
                addPath(result,"split:"+names[i],sources[i]);
            }
        }
        need(new java.util.HashSet<String>(result.values()).size()==result.size(),"PROFILE_APK_PATH_DUPLICATE");
        return result;
    }
    private static void addPath(Map<String,String> result,String key,String value)throws IOException{
        need(value!=null&&value.startsWith("/")&&value.endsWith(".apk")&&value.indexOf('\0')<0
                &&value.length()<=4096&&result.put(key,value)==null,"PROFILE_APK_PATH_INVALID");
    }
    private static Set<String> signers(PackageInfo info)throws Exception{
        need(info.signingInfo!=null,"PROFILE_SIGNING_INFO_UNKNOWN");
        Signature[] actual=info.signingInfo.getApkContentsSigners();
        need(actual!=null&&actual.length>0&&actual.length<=4,"PROFILE_SIGNERS_UNKNOWN");
        Set<String> result=new TreeSet<String>();
        for(Signature signature:actual)need(signature!=null&&result.add(ProfileIdentity.sha(signature.toByteArray())),
                "PROFILE_SIGNER_DUPLICATE");
        return result;
    }
    private synchronized String hashApk(String path,long deadline)throws Exception{
        StructStat before=Os.lstat(path);
        need(OsConstants.S_ISREG(before.st_mode)&&before.st_size>0&&before.st_size<=2147483648L,
                "PROFILE_APK_FILE_INVALID");
        String stat=statKey(before);CachedApk cached=hashedApks.get(path);
        // Reuse a digest only for the same kernel file identity, including nanosecond ctime/mtime.
        // PM user/UID/version/signers/enabled/suspended and the entire split set are still re-read.
        if(cached!=null&&cached.stat.equals(stat)){
            try(FileInputStream in=new FileInputStream(path)){
                need(sameStat(before,Os.fstat(in.getFD()))&&sameStat(before,Os.lstat(path)),
                        "PROFILE_APK_CACHE_IDENTITY_CHANGED");
            }
            checkTime(deadline);return cached.digest;
        }
        MessageDigest digest=MessageDigest.getInstance("SHA-256");long total=0;
        try(FileInputStream in=new FileInputStream(path)){
            need(sameStat(before,Os.fstat(in.getFD())),"PROFILE_APK_OPEN_CHANGED");
            byte[] buffer=new byte[65536];int count;
            while((count=in.read(buffer))!=-1){
                checkTime(deadline);total+=count;need(total<=before.st_size,"PROFILE_APK_SIZE_CHANGED");digest.update(buffer,0,count);
            }
            need(total==before.st_size&&sameStat(before,Os.fstat(in.getFD()))&&sameStat(before,Os.lstat(path)),
                    "PROFILE_APK_CHANGED_DURING_READ");
        }
        StringBuilder value=new StringBuilder(64);
        for(byte part:digest.digest())value.append(String.format(java.util.Locale.ROOT,"%02x",part&255));
        String result=value.toString();hashedApks.put(path,new CachedApk(stat,result));return result;
    }
    private static boolean sameStat(StructStat a,StructStat b)throws Exception{return statKey(a).equals(statKey(b));}
    private static String statKey(StructStat s)throws Exception{
        return s.st_dev+":"+s.st_ino+":"+s.st_mode+":"+s.st_uid+":"+s.st_gid+":"+s.st_size
                +":"+timespec(s,"st_mtim")+":"+timespec(s,"st_ctim");
    }
    private static String timespec(StructStat s,String name)throws Exception{
        Object value=StructStat.class.getField(name).get(s);need(value!=null,"PROFILE_APK_NANO_STAT_UNAVAILABLE");
        Object sec=value.getClass().getField("tv_sec").get(value),nano=value.getClass().getField("tv_nsec").get(value);
        need(sec instanceof Long&&nano instanceof Long&&(Long)nano>=0&&(Long)nano<1000000000L,
                "PROFILE_APK_NANO_STAT_UNAVAILABLE");
        return sec+":"+nano;
    }
    private static UserHandle handle(int id)throws Exception{
        return (UserHandle)UserHandle.class.getMethod("of",int.class).invoke(null,id);
    }
    private boolean userState(String method,UserHandle handle)throws Exception{
        Object value=UserManager.class.getMethod(method,UserHandle.class).invoke(users,handle);
        need(value instanceof Boolean,"PROFILE_USER_STATE_UNKNOWN");return (Boolean)value;
    }
    private static void checkTime(long deadline)throws IOException{
        if(deadline<=SystemClock.elapsedRealtime())throw new IOException("PROFILE_READ_DEADLINE");
    }
    private static void need(boolean v,String reason)throws IOException{if(!v)throw new IOException(reason);}
    private static int integer(Object o,String name)throws Exception{
        Object v=o.getClass().getField(name).get(o);need(v instanceof Integer,"PROFILE_USER_FIELD_INVALID");return (Integer)v;
    }
    private static boolean bool(Object o,String name)throws Exception{
        Object v=o.getClass().getField(name).get(o);need(v instanceof Boolean,"PROFILE_USER_FIELD_INVALID");return (Boolean)v;
    }
}
