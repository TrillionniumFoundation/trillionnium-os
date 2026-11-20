package org.trillionnium.hepta.background;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** The currently installed recovery code, explicitly separate from the historical broker. */
public final class RecoveryControllerIdentity {
    private RecoveryControllerIdentity(){}
    public static JSONObject read(Context context,int uid,long deadline)throws Exception{
        need(android.os.Build.VERSION.SDK_INT==36&&uid>=10000&&uid<90000,"PUBLIC_RECOVERY_CONTROLLER_PLATFORM");
        PackageManager pm=context.getPackageManager();
        String[] packages=pm.getPackagesForUid(uid);
        need(packages!=null&&packages.length==1&&PublicProfileAbsenceRecovery.CONTROLLER.equals(packages[0]),"PUBLIC_RECOVERY_CONTROLLER_UID");
        PackageInfo before=pm.getPackageInfo(PublicProfileAbsenceRecovery.CONTROLLER,PackageManager.GET_SIGNING_CERTIFICATES);
        String metadata=metadata(before,uid);File apk=new File(before.applicationInfo.sourceDir);
        need(apk.getAbsoluteFile().equals(apk.getCanonicalFile()),"PUBLIC_RECOVERY_CONTROLLER_APK_PATH");
        StructStat stat=Os.lstat(apk.getPath());
        need(OsConstants.S_ISREG(stat.st_mode)&&stat.st_size>0&&stat.st_size<=134217728,"PUBLIC_RECOVERY_CONTROLLER_APK_FILE");
        String original=statKey(stat);MessageDigest digest=MessageDigest.getInstance("SHA-256");long total=0;
        try(FileInputStream in=new FileInputStream(apk)){
            need(original.equals(statKey(Os.fstat(in.getFD()))),"PUBLIC_RECOVERY_CONTROLLER_APK_CHANGED");
            byte[] block=new byte[65536];int count;
            while((count=in.read(block))!=-1){check(deadline);total+=count;need(total<=stat.st_size,"PUBLIC_RECOVERY_CONTROLLER_APK_GREW");digest.update(block,0,count);}
            need(total==stat.st_size&&original.equals(statKey(Os.fstat(in.getFD())))&&original.equals(statKey(Os.lstat(apk.getPath()))),
                    "PUBLIC_RECOVERY_CONTROLLER_APK_CHANGED");
        }
        PackageInfo after=pm.getPackageInfo(PublicProfileAbsenceRecovery.CONTROLLER,PackageManager.GET_SIGNING_CERTIFICATES);
        need(metadata.equals(metadata(after,uid))&&Arrays.equals(packages,pm.getPackagesForUid(uid)),"PUBLIC_RECOVERY_CONTROLLER_PM_CHANGED");
        StringBuilder sha=new StringBuilder(64);for(byte b:digest.digest())sha.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        JSONObject result=new JSONObject().put("schema","hepta.recovery-controller-installation.v1")
                .put("package",PublicProfileAbsenceRecovery.CONTROLLER).put("user_id",0).put("uid",uid)
                .put("source_path",apk.getPath()).put("source_bytes",total).put("source_sha256",sha.toString())
                .put("version_code",after.getLongVersionCode()).put("signer_sha256",signers(after));
        PublicProfileAbsenceRecovery.requireController(result,uid);check(deadline);return result;
    }
    private static String metadata(PackageInfo p,int uid)throws Exception{
        ApplicationInfo a=p.applicationInfo;
        need(a!=null&&PublicProfileAbsenceRecovery.CONTROLLER.equals(p.packageName)&&p.packageName.equals(a.packageName)
                &&a.uid==uid&&a.enabled&&(a.flags&ApplicationInfo.FLAG_INSTALLED)!=0&&a.sourceDir!=null
                &&(a.splitSourceDirs==null||a.splitSourceDirs.length==0),"PUBLIC_RECOVERY_CONTROLLER_PM_IDENTITY");
        return a.sourceDir+":"+a.uid+":"+p.getLongVersionCode()+":"+p.firstInstallTime+":"+p.lastUpdateTime+":"+signers(p).toString();
    }
    private static JSONArray signers(PackageInfo p)throws Exception{
        need(p.signingInfo!=null,"PUBLIC_RECOVERY_CONTROLLER_SIGNERS_MISSING");Signature[] values=p.signingInfo.getApkContentsSigners();
        need(values!=null&&values.length>0&&values.length<=4,"PUBLIC_RECOVERY_CONTROLLER_SIGNERS_MISSING");
        TreeSet<String> out=new TreeSet<String>();for(Signature signature:values)need(signature!=null&&out.add(ProfileIdentity.sha(signature.toByteArray())),"PUBLIC_RECOVERY_CONTROLLER_SIGNERS_AMBIGUOUS");
        return new JSONArray(out);
    }
    private static String statKey(StructStat s)throws Exception{
        return s.st_dev+":"+s.st_ino+":"+s.st_mode+":"+s.st_uid+":"+s.st_gid+":"+s.st_size+":"+s.st_nlink
                +":"+time(s,"st_mtim")+":"+time(s,"st_ctim");
    }
    private static String time(StructStat s,String key)throws Exception{
        Object t=StructStat.class.getField(key).get(s);need(t!=null,"PUBLIC_RECOVERY_CONTROLLER_STAT_UNKNOWN");
        Object seconds=t.getClass().getField("tv_sec").get(t),nanos=t.getClass().getField("tv_nsec").get(t);
        need(seconds instanceof Long&&nanos instanceof Long&&(Long)nanos>=0&&(Long)nanos<1000000000L,"PUBLIC_RECOVERY_CONTROLLER_STAT_UNKNOWN");return seconds+":"+nanos;
    }
    private static void check(long deadline)throws Exception{need(SystemClock.elapsedRealtime()<deadline,"PUBLIC_RECOVERY_CONTROLLER_DEADLINE");}
    private static void need(boolean b,String code)throws Exception{PublicProfileAbsenceRecovery.need(b,code);}
}
