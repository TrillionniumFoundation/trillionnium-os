package org.trillionnium.hepta.local;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeMap;

/** Actual ordinary installed package identity. Never trusts a caller-supplied UID. */
final class WebHelperIdentity {
    private static final long MAX_APK=256L*1024*1024,MAX_SET=512L*1024*1024;
    final String packageName;
    final int uid;
    final long version;
    final String signer;
    final TreeMap<String,String> paths;
    final TreeMap<String,Stamp> stamps;
    final JSONObject evidence;
    private WebHelperIdentity(String name,int uid,long version,String signer,TreeMap<String,String> paths,
            TreeMap<String,Stamp> stamps,JSONObject evidence){
        this.packageName=name;this.uid=uid;this.version=version;this.signer=signer;
        this.paths=paths;this.stamps=stamps;this.evidence=evidence;
    }
    static void requirePeer(Context context,WebHelperIdentity controller,WebHelperIdentity helper)throws Exception{
        WebEvidenceJson.need(controller.packageName.equals(WebEvidenceProtocol.CONTROLLER_PACKAGE)
                &&helper.packageName.equals(WebEvidenceProtocol.HELPER_PACKAGE)
                &&controller.uid==Process.myUid()&&controller.uid!=helper.uid,"separate current controller/helper identity required");
        controller.requireUnchanged(context);helper.requireUnchanged(context);
        PackageManager pm=context.getPackageManager();
        WebEvidenceJson.need(pm.checkSignatures(controller.uid,helper.uid)==PackageManager.SIGNATURE_MATCH,
                "controller/helper current signatures differ");
        PackageInfo installed=info(pm,helper.packageName);
        WebEvidenceJson.need(helper.version==WebEvidenceProtocol.HELPER_VERSION_CODE
                &&WebEvidenceProtocol.HELPER_VERSION_NAME.equals(installed.versionName),"current formal helper release required");
        android.content.pm.ServiceInfo service=pm.getServiceInfo(
                new android.content.ComponentName(WebEvidenceProtocol.HELPER_PACKAGE,WebEvidenceProtocol.SERVICE_CLASS),0);
        WebEvidenceJson.need(service.exported&&service.enabled&&service.applicationInfo.enabled
                &&service.applicationInfo.uid==helper.uid
                &&WebEvidenceProtocol.PERMISSION.equals(service.permission),"explicit signature evidence service required");
        android.content.pm.PermissionInfo permission=pm.getPermissionInfo(WebEvidenceProtocol.PERMISSION,0);
        WebEvidenceJson.need(WebEvidenceProtocol.HELPER_PACKAGE.equals(permission.packageName)
                &&(permission.protectionLevel&android.content.pm.PermissionInfo.PROTECTION_MASK_BASE)
                    ==android.content.pm.PermissionInfo.PROTECTION_SIGNATURE
                &&pm.checkPermission(WebEvidenceProtocol.PERMISSION,controller.packageName)==PackageManager.PERMISSION_GRANTED,
                "signature evidence permission unavailable");
    }
    static WebHelperIdentity read(Context context,String name)throws Exception{
        WebEvidenceJson.need(name.equals(WebEvidenceProtocol.CONTROLLER_PACKAGE)||name.equals(WebEvidenceProtocol.HELPER_PACKAGE),"fixed package only");
        PackageManager pm=context.getPackageManager();PackageInfo info=info(pm,name);int uid=info.applicationInfo.uid;
        WebEvidenceJson.need(uid>=10000,"ordinary application UID required");String signer=signer(info);
        WebEvidenceJson.need(WebEvidenceProtocol.SIGNER_SHA256.equals(signer),"approved signer required");
        TreeMap<String,String> paths=paths(info.applicationInfo);TreeMap<String,Stamp> stamps=new TreeMap<String,Stamp>();
        JSONObject hashes=new JSONObject();long total=0;
        for(Map.Entry<String,String> entry:paths.entrySet()){
            Stamp before=Stamp.read(entry.getValue());total+=before.size;
            WebEvidenceJson.need(before.size>0&&before.size<=MAX_APK&&total<=MAX_SET,"APK byte budget");
            hashes.put(entry.getKey(),fileSha(entry.getValue(),before));stamps.put(entry.getKey(),before);
        }
        StringBuilder set=new StringBuilder();for(String logical:paths.keySet())set.append(logical).append('\t').append(hashes.getString(logical)).append('\n');
        JSONObject evidence=new JSONObject().put("package",name).put("uid",uid).put("version_code",info.getLongVersionCode())
                .put("apk_hashes",hashes).put("apk_set_sha256",WebEvidenceJson.sha(set.toString())).put("signer_sha256",signer);
        WebHelperIdentity out=new WebHelperIdentity(name,uid,info.getLongVersionCode(),signer,paths,stamps,evidence);
        out.requireUnchanged(context);return out;
    }
    void requireRequest(JSONObject claimed)throws Exception{
        WebEvidenceJson.keys(claimed,WebEvidenceProtocol.IDENTITY_KEYS);
        WebEvidenceJson.need(WebEvidenceBinding.canonical(claimed).equals(WebEvidenceBinding.canonical(evidence)),"installed identity differs");
    }
    void requireUnchanged(Context context)throws Exception{
        PackageInfo now=info(context.getPackageManager(),packageName);
        WebEvidenceJson.need(now.applicationInfo.uid==uid&&now.getLongVersionCode()==version&&signer.equals(signer(now))
                &&paths.equals(paths(now.applicationInfo)),"installed identity changed");
        for(String key:paths.keySet())WebEvidenceJson.need(stamps.get(key).same(Stamp.read(paths.get(key))),"installed APK changed");
    }
    private static PackageInfo info(PackageManager pm,String name)throws Exception{
        return pm.getPackageInfo(name,PackageManager.GET_SIGNING_CERTIFICATES);
    }
    private static String signer(PackageInfo info)throws Exception{
        WebEvidenceJson.need(info.signingInfo!=null&&!info.signingInfo.hasMultipleSigners(),"one current signer required");
        Signature[] certificates=info.signingInfo.getApkContentsSigners();
        WebEvidenceJson.need(certificates!=null&&certificates.length==1,"one actual certificate required");return WebEvidenceJson.sha(certificates[0].toByteArray());
    }
    private static TreeMap<String,String> paths(ApplicationInfo info)throws Exception{
        TreeMap<String,String> out=new TreeMap<String,String>();WebEvidenceJson.need(info.sourceDir!=null,"base APK path missing");out.put("base",info.sourceDir);
        String[] splits=info.splitSourceDirs,names=info.splitNames;
        WebEvidenceJson.need((splits==null||splits.length==0)==(names==null||names.length==0),"split identity missing");
        if(splits!=null&&splits.length>0){WebEvidenceJson.need(names!=null&&splits.length==names.length&&splits.length<=32,"split identity count");
            for(int i=0;i<splits.length;i++){WebEvidenceJson.need(names[i]!=null&&names[i].matches("[A-Za-z0-9_.-]{1,120}")&&splits[i]!=null,"split identity invalid");
                WebEvidenceJson.need(out.put("split:"+names[i],splits[i])==null,"duplicate split identity");}}
        return out;
    }
    private static String fileSha(String path,Stamp expected)throws Exception{
        FileDescriptor fd=Os.open(path,OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);
        try(FileInputStream in=new FileInputStream(fd)){
            WebEvidenceJson.need(expected.same(new Stamp(Os.fstat(fd))),"opened APK differs");MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] buffer=new byte[65536];long bytes=0;int n;while((n=in.read(buffer))!=-1){bytes+=n;WebEvidenceJson.need(bytes<=expected.size,"APK grew");digest.update(buffer,0,n);}
            WebEvidenceJson.need(bytes==expected.size&&expected.same(new Stamp(Os.fstat(fd)))&&expected.same(Stamp.read(path)),"APK changed while hashing");
            byte[] sha=digest.digest();StringBuilder hex=new StringBuilder(64);for(byte b:sha)hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return hex.toString();
        }
    }
    private static final class Stamp {
        final long dev,ino,size,mtime,ctime;final int mode;final long links;
        Stamp(StructStat s){dev=s.st_dev;ino=s.st_ino;size=s.st_size;mtime=s.st_mtime;ctime=s.st_ctime;mode=s.st_mode;links=s.st_nlink;}
        static Stamp read(String path)throws Exception{Stamp s=new Stamp(Os.lstat(path));WebEvidenceJson.need(OsConstants.S_ISREG(s.mode)&&s.links==1,"regular immutable APK required");return s;}
        boolean same(Stamp s){return dev==s.dev&&ino==s.ino&&size==s.size&&mtime==s.mtime&&ctime==s.ctime&&mode==s.mode&&links==s.links;}
    }
}
