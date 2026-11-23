package org.trillionnium.hepta.background;

import android.content.*;
import android.content.pm.*;
import android.os.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Actual per-user PM reader/native-home resolver, with explicit synthetic Android ports. */
public final class ProfilePackagesHostTest {
    static final String X=ProfileTarget.XIAOMI,C=ProfileTarget.CTRIP;
    static final String XL="com.xiaomi.shop2.activity.SyntheticLauncher",CL="ctrip.android.view.SyntheticLauncher";
    static int assertions,counter;static Path work;
    static final List<String> cases=new ArrayList<String>();
    interface Work {void run()throws Exception;}
    static void yes(boolean value){assertions++;if(!value)throw new AssertionError("target-user package reader boundary");}
    static void test(String name,Work run)throws Exception{run.run();cases.add(name);}
    static void reject(String reason,Work run)throws Exception{
        try{run.run();}catch(Exception expected){yes(expected.getMessage()!=null&&expected.getMessage().contains(reason));return;}
        throw new AssertionError("accepted instead of "+reason);
    }
    static final class Pm extends PackageManager {
        final int user;final String apk;final List<String> reads=new ArrayList<String>();
        int packageReads,launcherReads,homeQueries;boolean missingHome,duplicateHome,badHomeComponent,badHomeUid,badLauncherUid;
        boolean changedLauncher,changedVersion,homePermission,homeForbidden,launcherNotSingleTask,homeNotSingleTask;
        Pm(int user,String path){this.user=user;apk=path;}
        int uid(String pkg){return user*100000+(X.equals(pkg)?10355:10367);}
        ApplicationInfo app(String pkg){ApplicationInfo a=new ApplicationInfo();a.packageName=pkg;a.uid=uid(pkg);a.sourceDir=apk;return a;}
        ActivityInfo activity(String pkg,String cls){ActivityInfo a=new ActivityInfo();a.packageName=pkg;a.name=cls;a.applicationInfo=app(pkg);
            a.launchMode=2;a.taskAffinity=pkg;return a;}
        @Override public PackageInfo getPackageInfo(String pkg,int flags)throws NameNotFoundException{
            reads.add(pkg);packageReads++;if(!ProfileTarget.supportsPackage(pkg))throw new NameNotFoundException(pkg);
            PackageInfo p=new PackageInfo();p.packageName=pkg;p.applicationInfo=app(pkg);p.version=X.equals(pkg)?20261010:1779;
            if(changedVersion&&packageReads>1)p.version++;
            p.signingInfo=new SigningInfo(new Signature((pkg+":synthetic-signer").getBytes(StandardCharsets.UTF_8)));return p;
        }
        @Override public Intent getLaunchIntentForPackage(String pkg){
            launcherReads++;String cls=X.equals(pkg)?XL:CL;if(changedLauncher&&launcherReads>1)cls+="Changed";
            return new Intent(Intent.ACTION_MAIN).setPackage(pkg).setComponent(new ComponentName(pkg,cls));
        }
        @Override public ActivityInfo getActivityInfo(ComponentName c,int flags){
            ActivityInfo a=activity(c.getPackageName(),c.getClassName());
            if(BackgroundOwnedSingleTask.COMPONENT.equals(c.getPackageName()+"/"+c.getClassName())){
                if(homePermission)a.permission="synthetic.permission.NOT_GRANTED";
                if(homeForbidden)a.flags=ActivityInfo.FLAG_ALLOW_TASK_REPARENTING;
                if(homeNotSingleTask)a.launchMode=0;
            }else if(X.equals(c.getPackageName())){
                if(badLauncherUid)a.applicationInfo.uid=10355;
                if(launcherNotSingleTask)a.launchMode=0;
            }
            return a;
        }
        @Override public List<ResolveInfo> queryIntentActivities(Intent query,int flags){
            homeQueries++;yes(BackgroundOwnedSingleTask.ACTION.equals(query.getAction())&&X.equals(query.getPackage()));
            if(missingHome)return Collections.emptyList();
            ResolveInfo r=new ResolveInfo();r.activityInfo=getActivityInfo(ComponentName.unflattenFromString(BackgroundOwnedSingleTask.COMPONENT),0);
            if(badHomeComponent)r.activityInfo.name="com.xiaomi.shop2.activity.Other";
            if(badHomeUid)r.activityInfo.applicationInfo.uid=10355;
            return duplicateHome?Arrays.asList(r,r):Collections.singletonList(r);
        }
    }
    static final class Env {
        final UserManager users=new UserManager();final Pm personal,profile;final Context shell;final ProfilePackages reader;
        Env()throws Exception{
            android.os.Process.uid=0;Build.VERSION.SDK_INT=36;android.app.ActivityManager.current=0;SystemClock.now=1000;
            Context.contexts.clear();Path dir=work.resolve("case-"+(++counter));Files.createDirectories(dir);
            Path apk=dir.resolve("synthetic.apk");Files.write(apk,"synthetic-apk-no-device-code".getBytes(StandardCharsets.UTF_8));
            personal=new Pm(0,apk.toString());profile=new Pm(10,apk.toString());
            shell=new Context(0,personal,users);new Context(10,profile,users);reader=new ProfilePackages(shell);
        }
        ProfilePackages.Readback read(String pkg)throws Exception{return reader.read(10,pkg,true,5000);}
    }
    public static void main(String[] args)throws Exception{
        work=Paths.get(args[0]);Files.createDirectories(work);
        test("xiaomi_reads_only_selected_user_and_registered_empty_home",()->{
            Env e=new Env();ProfilePackages.Readback r=e.read(X);
            yes(e.personal.reads.isEmpty()&&e.profile.reads.equals(Arrays.asList(X,X)));
            yes(r.target.fullUid==1010355&&r.target.profile.userId==10&&r.target.profile.serial==20);
            yes(BackgroundOwnedSingleTask.COMPONENT.equals(r.target.component)&&e.profile.homeQueries==2);
            yes(r.target.versionCode==20261010&&r.target.apkHashes.size()==1&&r.target.signerSha256.size()==1);
            Intent intent=ProfilePackages.launchIntent(r.target);
            yes(BackgroundOwnedSingleTask.ACTION.equals(intent.getAction())&&X.equals(intent.getPackage()));
            yes(intent.getComponent().equals(ComponentName.unflattenFromString(r.target.component))&&intent.getCategories().isEmpty());
            yes(intent.getFlags()==(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_MULTIPLE_TASK));
        });
        test("ctrip_keeps_its_actual_launcher_and_no_home_query",()->{
            Env e=new Env();ProfilePackages.Readback r=e.read(C);Intent intent=ProfilePackages.launchIntent(r.target);
            yes(r.target.component.equals(C+"/"+CL)&&r.target.fullUid==1010367&&e.profile.homeQueries==0&&e.personal.reads.isEmpty());
            yes(Intent.ACTION_MAIN.equals(intent.getAction())&&intent.getCategories().equals(Collections.singleton(Intent.CATEGORY_LAUNCHER)));
        });
        test("both_apps_share_identity_but_not_installation",()->{
            Env e=new Env();ProfileTarget x=e.read(X).target,c=e.read(C).target;
            yes(x.profile.same(c.profile)&&!x.same(c)&&x.fullUid!=c.fullUid&&x.packageName.equals(X));
        });
        test("no_native_home_never_falls_back_to_launcher",()->{Env e=new Env();e.profile.missingHome=true;reject("OWNED_HOME_REGISTRATION_NOT_UNIQUE",()->e.read(X));yes(e.personal.reads.isEmpty());});
        test("duplicate_home_registration_refused",()->{Env e=new Env();e.profile.duplicateHome=true;reject("OWNED_HOME_REGISTRATION_NOT_UNIQUE",()->e.read(X));});
        test("unknown_home_component_refused",()->{Env e=new Env();e.profile.badHomeComponent=true;reject("OWNED_HOME_REGISTRATION_CHANGED",()->e.read(X));});
        test("user0_home_uid_cannot_stand_in_for_profile_uid",()->{Env e=new Env();e.profile.badHomeUid=true;reject("OWNED_HOME_INSTALLED_IDENTITY_CHANGED",()->e.read(X));});
        test("user0_launcher_uid_cannot_stand_in_for_profile_uid",()->{Env e=new Env();e.profile.badLauncherUid=true;reject("OWNED_HOME_INSTALLED_IDENTITY_CHANGED",()->e.read(X));});
        test("launcher_must_be_the_verified_single_task_provider",()->{Env e=new Env();e.profile.launcherNotSingleTask=true;reject("PROFILE_NATIVE_HOME_UNAVAILABLE",()->e.read(X));});
        test("home_launch_mode_changed_refused",()->{Env e=new Env();e.profile.homeNotSingleTask=true;reject("OWNED_HOME_REGISTRATION_CHANGED",()->e.read(X));});
        test("home_required_permission_not_bypassed",()->{Env e=new Env();e.profile.homePermission=true;reject("PROFILE_LAUNCH_CAPABILITY_UNAVAILABLE",()->e.read(X));});
        test("home_reparent_flag_not_bypassed",()->{Env e=new Env();e.profile.homeForbidden=true;reject("PROFILE_LAUNCH_CAPABILITY_UNAVAILABLE",()->e.read(X));});
        test("launcher_identity_change_during_read_refused",()->{Env e=new Env();e.profile.changedLauncher=true;reject("PROFILE_LAUNCHER_CHANGED_DURING_READ",()->e.read(X));});
        test("apk_version_change_during_read_refused",()->{Env e=new Env();e.profile.changedVersion=true;reject("PROFILE_INSTALLATION_CHANGED_DURING_READ",()->e.read(X));});
        test("profile_serial_reuse_during_read_refused",()->{Env e=new Env();e.users.changeSerial=true;reject("PROFILE_STATE_CHANGED_DURING_READ",()->e.read(X));});
        test("locked_profile_refused_before_pm_read",()->{Env e=new Env();e.users.unlocked=false;reject("PROFILE_NOT_RUNNING_UNLOCKED",()->e.read(X));yes(e.profile.reads.isEmpty());});
        test("deadline_refused_before_pm_read",()->{Env e=new Env();reject("PROFILE_READ_DEADLINE",()->e.reader.read(10,X,true,1000));yes(e.profile.reads.isEmpty());});
        test("notes_profile_is_not_admitted",()->{Env e=new Env();reject("PROFILE_PACKAGE_NOT_SUPPORTED",()->e.read("com.motorola.stylus"));yes(e.profile.reads.isEmpty());});
        test("forged_xiaomi_component_cannot_create_launch_intent",()->{
            Env e=new Env();ProfileTarget x=e.read(X).target;
            ProfileTarget forged=new ProfileTarget(x.profile,x.fullUid,X,X+"/"+XL,x.versionCode,x.apkHashes,x.signerSha256);
            reject("PROFILE_NATIVE_HOME_COMPONENT_INVALID",()->ProfilePackages.launchIntent(forged));
        });
        System.out.println(new JSONObject().put("all_pass",true).put("cases",cases.size()).put("assertions",assertions)
                .put("case_names",new JSONArray(cases)).put("actual_production_package_reader",true)
                .put("actual_registered_home_methods",true).put("android_pm_and_clock_are_fakes",true).put("phone_actions",0));
    }
}
