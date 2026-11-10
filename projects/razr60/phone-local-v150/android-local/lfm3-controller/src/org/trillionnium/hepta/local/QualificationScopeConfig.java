package org.trillionnium.hepta.local;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** App-private opt-in loader; a captured task never reloads into a weaker mode. */
final class QualificationScopeConfig {
    private QualificationScopeConfig(){}
    static final class Bound {
        final Context context;
        final String taskId,expectedSha256;
        final File scopePath;
        String actualSha256,buildIdentitySha256,runtimeConfigSha256;
        byte[] raw,buildBytes;
        QualificationScope.Config config;
        QualificationScope.Gate gate=new QualificationScope.Gate(null);
        MobiMindPrivateFiles.Read scopeFile,runtimeFile;
        final List<Installed> installed=new ArrayList<Installed>();
        private String failure;
        Bound(Context context,String task,String expected){this.context=context;taskId=task;expectedSha256=expected;scopePath=new File(context.getFilesDir(),QualificationScope.FILE_NAME);}
        boolean restricted(){return raw!=null||expectedSha256!=null||failure!=null;}
        synchronized void requireReady(){if(failure!=null)throw new QualificationScope.Violation(failure);}
        synchronized void refuse(String reason){if(failure==null)failure=reason;gate.fail(reason);}
        void verifyUnchanged(){
            requireReady();
            try{
                if(config==null){QualificationScope.require(!MobiMindPrivateFiles.exists(scopePath),"scope mode changed during unrestricted task");return;}
                scopeFile.unchangedPath();
                MobiMindPrivateFiles.Read fresh=MobiMindPrivateFiles.read(scopePath,QualificationScope.MAX_CONFIG_BYTES,true);
                QualificationScope.require(actualSha256.equals(QualificationScope.hash(fresh.bytes)),"scope bytes changed during task");
                runtimeFile.unchangedPath();
                QualificationScope.require(runtimeConfigSha256.equals(QualificationScope.hash(MobiMindPrivateFiles.read(runtimeFile.path,4096,true).bytes)),"runtime bytes changed during task");
                for(Installed identity:installed)identity.verify(context);
                QualificationScope.require(config.launcherComponent.equals(home(context)),"default HOME changed during task");
            }catch(Exception error){refuse(error.getMessage());throw new QualificationScope.Violation(failure);}
        }
        synchronized JSONObject evidence(){
            try{return new JSONObject().put("schema","hepta.qualification-task-scope.v1").put("task_id",taskId)
                    .put("expected_scope_sha256",nullable(expectedSha256)).put("actual_scope_sha256",nullable(actualSha256))
                    .put("restricted",restricted()).put("scope_loaded",config!=null).put("qualification_id",config==null?JSONObject.NULL:config.qualificationId)
                    .put("build_identity_sha256",nullable(buildIdentitySha256)).put("runtime_config_sha256",nullable(runtimeConfigSha256))
                    .put("scope_refused",failure!=null||gate.refusal()!=null).put("refusal",nullable(failure!=null?failure:gate.refusal()))
                    .put("last_check",new JSONObject(gate.proof()));}
            catch(Exception error){throw new IllegalStateException("scope evidence cannot be encoded",error);}
        }
    }
    static Bound capture(Context context,String taskId,String expected,LocalRuntimeConfig runtime){
        Bound bound=new Bound(context,taskId,expected);
        try{
            QualificationScope.expected(expected);
            if(!MobiMindPrivateFiles.exists(bound.scopePath)){
                QualificationScope.require(expected==null,"expected scope file missing");return bound;
            }
            bound.scopeFile=MobiMindPrivateFiles.read(bound.scopePath,QualificationScope.MAX_CONFIG_BYTES,true);
            bound.raw=bound.scopeFile.bytes;bound.actualSha256=QualificationScope.hash(bound.raw);
            QualificationScope.require(expected==null||expected.equals(bound.actualSha256),"expected scope SHA mismatch");
            bound.config=QualificationScope.Config.parse(bound.raw);bound.gate=new QualificationScope.Gate(bound.config);
            try(InputStream input=context.getAssets().open(QualificationScope.BUILD_ASSET)){bound.buildBytes=bounded(input,131072);}
            bound.buildIdentitySha256=QualificationScope.hash(bound.buildBytes);
            QualificationScope.require(bound.config.buildIdentitySha256.equals(bound.buildIdentitySha256),"packaged build identity mismatch");
            JSONObject asset=new JSONObject(new String(bound.buildBytes,StandardCharsets.UTF_8));
            QualificationScope.require("hepta.actual-build-inputs.v1".equals(asset.getString("schema"))
                    &&asset.getLong("version_code")==bound.config.heptaVersionCode&&asset.getJSONArray("source_inputs").length()>0,"build identity contract mismatch");
            bound.runtimeFile=MobiMindPrivateFiles.read(new File(context.getFilesDir(),"model/runtime-config.json"),4096,true);
            bound.runtimeConfigSha256=QualificationScope.hash(bound.runtimeFile.bytes);
            QualificationScope.require(bound.config.runtimeConfigSha256.equals(bound.runtimeConfigSha256),"runtime configuration hash mismatch");
            JSONObject runtimeJson=new JSONObject(new String(bound.runtimeFile.bytes,StandardCharsets.UTF_8));
            QualificationScope.require(runtime.profile.id.equals(runtimeJson.getString("model_profile"))&&runtime.compute.equals(runtimeJson.getString("compute"))
                    &&runtime.contextTokens==runtimeJson.getInt("context_tokens")&&runtime.threads==runtimeJson.getInt("threads"),"loaded engine configuration differs from scope");
            Installed self=Installed.capture(context,context.getPackageName());bound.installed.add(self);
            QualificationScope.require(self.uid==android.os.Process.myUid()&&self.version==bound.config.heptaVersionCode
                    &&self.apks.size()==1&&bound.config.heptaApkSha256.equals(self.apks.get("base").sha256),"installed Hepta identity mismatch");
            for(QualificationScope.Role role:bound.config.roles.values()){
                Installed identity=Installed.capture(context,role.packageName);bound.installed.add(identity);
                QualificationScope.require(identity.uid==role.uid&&identity.version==role.versionCode&&identity.apkSetSha256.equals(role.apkSetSha256),"installed role identity mismatch: "+role.role);
            }
            QualificationScope.require(bound.config.launcherComponent.equals(home(context)),"default HOME differs from scope");
            bound.verifyUnchanged();
        }catch(Exception error){bound.refuse(error.getMessage()==null?error.getClass().getSimpleName():error.getMessage());}
        return bound;
    }
    static Object nullable(Object value){return value==null?JSONObject.NULL:value;}
    static String home(Context context)throws Exception{
        Intent intent=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME);
        ResolveInfo info=context.getPackageManager().resolveActivity(intent,PackageManager.MATCH_DEFAULT_ONLY);
        QualificationScope.require(info!=null&&info.activityInfo!=null&&info.activityInfo.enabled&&info.activityInfo.exported,"default HOME is unknown");
        return new ComponentName(info.activityInfo.packageName,info.activityInfo.name).flattenToString();
    }
    private static byte[] bounded(InputStream input,int limit)throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] block=new byte[8192];int count;
        while((count=input.read(block))!=-1){QualificationScope.require(out.size()+count<=limit,"build identity byte bound");out.write(block,0,count);}return out.toByteArray();
    }
    /** APK-set hash = SHA256 of sorted UTF-8 `base|split:name<TAB>sha256<LF>` rows. */
    private static final class Installed {
        final String packageName,apkSetSha256;
        final int uid;
        final long version;
        final Map<String,Apk> apks;
        Installed(PackageInfo info,Map<String,Apk> values){packageName=info.packageName;uid=info.applicationInfo.uid;version=info.getLongVersionCode();apks=values;
            StringBuilder rows=new StringBuilder();for(Map.Entry<String,Apk> e:apks.entrySet())rows.append(e.getKey()).append('\t').append(e.getValue().sha256).append('\n');
            apkSetSha256=QualificationScope.hash(rows.toString().getBytes(StandardCharsets.UTF_8));}
        static Installed capture(Context context,String pkg)throws Exception{
            PackageInfo info=context.getPackageManager().getPackageInfo(pkg,0);Map<String,String> paths=paths(info);
            Map<String,Apk> values=new TreeMap<String,Apk>();for(Map.Entry<String,String> entry:paths.entrySet())values.put(entry.getKey(),Apk.capture(entry.getValue()));return new Installed(info,values);
        }
        void verify(Context context)throws Exception{
            PackageInfo info=context.getPackageManager().getPackageInfo(packageName,0);Map<String,String> paths=paths(info);
            QualificationScope.require(info.applicationInfo.uid==uid&&info.getLongVersionCode()==version&&paths.keySet().equals(apks.keySet()),"installed identity changed: "+packageName);
            for(Map.Entry<String,String> entry:paths.entrySet()){Apk old=apks.get(entry.getKey());QualificationScope.require(old.path.equals(entry.getValue()),"APK path changed");old.verify();}
        }
        private static Map<String,String> paths(PackageInfo info){
            ApplicationInfo app=info.applicationInfo;QualificationScope.require(app!=null&&app.enabled&&info.packageName.equals(app.packageName)&&app.sourceDir!=null,"installed package missing or disabled");
            Map<String,String> paths=new TreeMap<String,String>();paths.put("base",app.sourceDir);
            String[] names=info.splitNames,files=app.splitSourceDirs;
            QualificationScope.require((names==null&&files==null)||(names!=null&&files!=null&&names.length==files.length),"APK splits unknown");
            if(names!=null)for(int i=0;i<names.length;i++){
                QualificationScope.require(names[i]!=null&&names[i].matches("[a-zA-Z0-9_.-]+")&&files[i]!=null&&!paths.containsKey("split:"+names[i]),"APK split name invalid");paths.put("split:"+names[i],files[i]);}
            return paths;
        }
    }
    private static final class Apk {
        final String path,sha256;final StructStat stat;
        Apk(String path,String sha,StructStat stat){this.path=path;sha256=sha;this.stat=stat;}
        static Apk capture(String path)throws Exception{
            FileDescriptor fd=Os.open(path,OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);
            try(FileInputStream input=new FileInputStream(fd)){
                StructStat before=Os.fstat(fd);QualificationScope.require(OsConstants.S_ISREG(before.st_mode)&&before.st_size>0&&(before.st_mode&0022)==0,"APK not a read-only regular installation file");
                MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] block=new byte[131072];long total=0;int n;
                while((n=input.read(block))!=-1){total+=n;QualificationScope.require(total<=before.st_size,"APK changed while hashing");digest.update(block,0,n);}
                QualificationScope.require(total==before.st_size&&same(before,Os.fstat(fd))&&same(before,Os.lstat(path)),"APK changed while hashing");
                StringBuilder hash=new StringBuilder();for(byte b:digest.digest())hash.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return new Apk(path,hash.toString(),before);
            }
        }
        void verify()throws Exception{QualificationScope.require(same(stat,Os.lstat(path)),"APK installation changed during task");}
        private static boolean same(StructStat a,StructStat b){return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_uid==b.st_uid
                &&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink&&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;}
    }
}
