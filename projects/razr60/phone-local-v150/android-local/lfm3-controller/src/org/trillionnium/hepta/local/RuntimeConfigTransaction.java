package org.trillionnium.hepta.local;

import android.content.Context;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.json.JSONObject;

/** Private configuration transaction only. Never reads or changes task/lease journals. */
final class RuntimeConfigTransaction {
    private static final int CONFIG_LIMIT=4096,POINTER_LIMIT=2048,INTENT_LIMIT=8192;
    private static final String POINTER="hepta.local-model-settings-pointer.v1";
    private static final String INTENT="hepta.local-model-settings-intent.v1";
    final File files,root,directory;
    final String id;
    final Snapshot before,after,previousLast;
    final boolean recoveringPending;
    private final MobiMindPrivateFiles.Read intentRead,beforeRead,afterRead,lastBackupRead;
    private Snapshot applied;

    static final class Snapshot {
        final File path;
        final boolean exists;
        final byte[] bytes;
        final MobiMindPrivateFiles.Read read;
        Snapshot(File path,boolean exists,byte[] bytes,MobiMindPrivateFiles.Read read){
            this.path=path;this.exists=exists;this.bytes=bytes.clone();this.read=read;
        }
        String sha(){return MobiMindContract.sha(bytes);}
        boolean sameBytes(Snapshot other){return other!=null&&exists==other.exists&&Arrays.equals(bytes,other.bytes);}
        void unchanged()throws Exception{
            if(read!=null)read.unchangedPath();
            Snapshot fresh=read(path,path.getName().equals("runtime-config.json")?CONFIG_LIMIT:POINTER_LIMIT);
            if(!sameBytes(fresh))throw new IOException("configuration transaction source changed");
        }
    }
    private RuntimeConfigTransaction(File files,File root,File directory,String id,Snapshot before,
            Snapshot after,Snapshot previousLast,boolean recovery,MobiMindPrivateFiles.Read intent,
            MobiMindPrivateFiles.Read oldRaw,MobiMindPrivateFiles.Read newRaw,MobiMindPrivateFiles.Read lastRaw){
        this.files=files;this.root=root;this.directory=directory;this.id=id;this.before=before;this.after=after;
        this.previousLast=previousLast;this.recoveringPending=recovery;
        intentRead=intent;beforeRead=oldRaw;afterRead=newRaw;lastBackupRead=lastRaw;
    }
    /** Only a framework Context root may contain Android's platform parent-directory alias. */
    static File contextFiles(Context context)throws Exception{
        Context application=context.getApplicationContext();
        File path=application==null?null:application.getFilesDir();
        if(path==null||!path.isAbsolute())throw new IOException("private Context files path unavailable");
        // lstat the original leaf before resolving parents: a files symlink is never admitted.
        StructStat before=Os.lstat(path.getPath());
        if(!OsConstants.S_ISDIR(before.st_mode)||before.st_uid!=android.os.Process.myUid())
            throw new IOException("private Context files identity unavailable");
        File canonical=path.getCanonicalFile();
        StructStat resolved=Os.lstat(canonical.getPath());
        if(!sameDirectory(before,resolved)||!sameDirectory(before,Os.lstat(path.getPath()))
                ||!canonical.equals(path.getCanonicalFile())
                ||!sameDirectory(resolved,Os.lstat(canonical.getPath())))
            throw new IOException("private Context files identity changed");
        return canonical;
    }
    private static boolean sameDirectory(StructStat a,StructStat b){
        return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid
                &&a.st_gid==b.st_gid&&a.st_mode==b.st_mode;
    }
    private static File canonicalFiles(File files)throws Exception{
        File value=files.getCanonicalFile();
        if(!value.equals(files.getAbsoluteFile()))throw new IOException("private files path is aliased");
        StructStat s=Os.lstat(value.getPath());
        if(!OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=android.os.Process.myUid())
            throw new IOException("private files identity unavailable");
        return value;
    }
    private static File configPath(File files)throws Exception{
        File root=canonicalFiles(files),model=new File(root,"model"),path=new File(model,"runtime-config.json");
        if(!model.getCanonicalFile().equals(model)||!path.getCanonicalFile().equals(path))
            throw new IOException("runtime-config path is aliased");
        return path;
    }
    private static File settingsRoot(File files,boolean create)throws Exception{
        File parent=canonicalFiles(files),path=new File(parent,"runtime-settings");
        if(!path.getCanonicalFile().equals(path))throw new IOException("settings path is aliased");
        if(!MobiMindPrivateFiles.exists(path)){
            if(!create)return path;
            Os.mkdir(path.getPath(),0700);MobiMindPrivateFiles.syncDirectory(parent);
        }
        StructStat s=Os.lstat(path.getPath());
        if(!OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=android.os.Process.myUid()||(s.st_mode&0777)!=0700)
            throw new IOException("settings directory must be private and app-owned");
        return path;
    }
    private static Snapshot read(File path,int limit)throws Exception{
        if(!MobiMindPrivateFiles.exists(path))return new Snapshot(path,false,new byte[0],null);
        MobiMindPrivateFiles.Read r=MobiMindPrivateFiles.read(path,limit,true);
        return new Snapshot(path,true,r.bytes,r);
    }
    static Snapshot current(File files)throws Exception{return read(configPath(files),CONFIG_LIMIT);}
    static boolean pending(File files)throws Exception{
        File root=settingsRoot(files,false);
        return MobiMindPrivateFiles.exists(root)&&MobiMindPrivateFiles.exists(new File(root,"pending.json"));
    }
    static boolean restoreAvailable(File files)throws Exception{
        File root=settingsRoot(files,false);
        return MobiMindPrivateFiles.exists(root)&&(MobiMindPrivateFiles.exists(new File(root,"pending.json"))
                ||MobiMindPrivateFiles.exists(new File(root,"last.json")));
    }
    static LocalRuntimeConfig decode(Snapshot value)throws Exception{
        if(!value.exists)return LocalRuntimeConfig.defaults();
        if(value.bytes.length==0||value.bytes.length>CONFIG_LIMIT)throw new IOException("configuration size outside bound");
        JSONObject object=new JSONObject(new String(value.bytes,StandardCharsets.UTF_8));
        Map<String,Object> fields=new HashMap<String,Object>();Iterator<String> names=object.keys();
        while(names.hasNext()){String name=names.next();fields.put(name,object.get(name));}
        return LocalRuntimeConfig.fromFields(fields);
    }
    static void requireText(LocalRuntimeConfig config)throws IOException{
        if(config==null||(config.profile!=ModelProfile.LFM3&&config.profile!=ModelProfile.LFM25_8B_A1B)
                ||config.visualObservationOnly||(!"npu".equals(config.compute)&&!"gpu".equals(config.compute)))
            throw new IOException("settings admit only the two pinned text models and explicit NPU/GPU");
    }
    static byte[] selected(String profile,String compute)throws Exception{
        ModelProfile model=ModelProfile.named(profile);
        LocalRuntimeConfig config=new LocalRuntimeConfig(model,compute,8192,4);requireText(config);
        return new JSONObject().put("schema","hepta.local-runtime.v2").put("model_profile",model.id)
                .put("compute",compute).put("context_tokens",8192).put("threads",4)
                .toString(2).getBytes(StandardCharsets.UTF_8);
    }
    private static JSONObject object(byte[] raw,String schema,String... names)throws Exception{
        JSONObject value=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        Set<String> keys=new HashSet<String>();Iterator<String> it=value.keys();while(it.hasNext())keys.add(it.next());
        Set<String> wanted=new HashSet<String>(Arrays.asList(names));wanted.add("schema");
        if(!wanted.equals(keys)||!schema.equals(value.opt("schema")))throw new IOException("settings record schema differs");
        return value;
    }
    private static byte[] pointer(String id)throws Exception{
        if(id==null||!id.matches("[0-9a-f]{32}"))throw new IOException("invalid settings transaction id");
        return new JSONObject().put("schema",POINTER).put("id",id).toString().getBytes(StandardCharsets.UTF_8);
    }
    /** Publish only a completely persisted pointer; an incomplete temp is never the startup marker. */
    private static void publishPointerIfAbsent(File path,String id)throws Exception{
        byte[] raw=pointer(id);
        if(MobiMindPrivateFiles.exists(path))throw new IOException("settings pointer already exists");
        File temporary=new File(path.getParentFile(),"pending-"+id+"-"+UUID.randomUUID().toString().replace("-","")+".new");
        MobiMindPrivateFiles.writeNew(temporary,raw);
        if(MobiMindPrivateFiles.exists(path))throw new IOException("settings pointer appeared before publication");
        Os.rename(temporary.getPath(),path.getPath());MobiMindPrivateFiles.syncDirectory(path.getParentFile());
        Snapshot published=read(path,POINTER_LIMIT);
        if(!published.exists||!Arrays.equals(raw,published.bytes))throw new IOException("settings pointer publication differs");
        published.unchanged();
    }
    private static String pointerId(byte[] raw)throws Exception{
        Object value=object(raw,POINTER,"id").get("id");
        if(!(value instanceof String)||!((String)value).matches("[0-9a-f]{32}"))
            throw new IOException("invalid settings pointer");
        return (String)value;
    }
    private static boolean bool(JSONObject value,String name)throws Exception{
        Object raw=value.get(name);if(!(raw instanceof Boolean))throw new IOException("settings boolean type differs");
        return (Boolean)raw;
    }
    private static void hash(JSONObject value,String name,byte[] raw)throws Exception{
        if(!MobiMindContract.sha(raw).equals(value.get(name)))throw new IOException("settings original bytes differ");
    }
    static RuntimeConfigTransaction prepare(File files,byte[] target,boolean targetExists)throws Exception{
        File canonical=canonicalFiles(files),root=settingsRoot(canonical,true);
        if(pending(canonical))throw new IOException("an earlier settings transaction requires explicit restore");
        Snapshot before=current(canonical);requireText(decode(before));
        Snapshot after=new Snapshot(before.path,targetExists,target,null);requireText(decode(after));
        if(!targetExists&&target.length!=0)throw new IOException("absent configuration cannot carry bytes");
        if(before.sameBytes(after))throw new IOException("the selected configuration is already exact");
        Snapshot last=read(new File(root,"last.json"),POINTER_LIMIT);
        if(last.exists)pointerId(last.bytes);
        String id=UUID.randomUUID().toString().replace("-","");
        File directory=new File(root,id);Os.mkdir(directory.getPath(),0700);MobiMindPrivateFiles.syncDirectory(root);
        MobiMindPrivateFiles.writeNew(new File(directory,"previous.raw"),before.bytes);
        MobiMindPrivateFiles.writeNew(new File(directory,"selected.raw"),after.bytes);
        MobiMindPrivateFiles.writeNew(new File(directory,"previous-last.raw"),last.bytes);
        byte[] intent=new JSONObject().put("schema",INTENT).put("id",id).put("app_uid",android.os.Process.myUid())
                .put("old_exists",before.exists).put("old_sha256",before.sha())
                .put("new_exists",after.exists).put("new_sha256",after.sha())
                .put("last_exists",last.exists).put("last_sha256",last.sha()).toString(2).getBytes(StandardCharsets.UTF_8);
        MobiMindPrivateFiles.writeNew(new File(directory,"intent.json"),intent);
        before.unchanged();last.unchanged();
        publishPointerIfAbsent(new File(root,"pending.json"),id);
        RuntimeConfigTransaction result=load(canonical,id,false);
        if(!result.before.sameBytes(before)||!result.after.sameBytes(after)||!result.previousLast.sameBytes(last))
            throw new IOException("settings intent readback differs");
        return new RuntimeConfigTransaction(canonical,root,directory,id,before,after,last,false,
                result.intentRead,result.beforeRead,result.afterRead,result.lastBackupRead);
    }
    private static RuntimeConfigTransaction load(File files,String id,boolean recovery)throws Exception{
        pointer(id);File canonical=canonicalFiles(files),root=settingsRoot(canonical,false),directory=new File(root,id);
        if(!directory.getCanonicalFile().equals(directory))throw new IOException("settings record directory is aliased");
        StructStat st=Os.lstat(directory.getPath());
        if(!OsConstants.S_ISDIR(st.st_mode)||st.st_uid!=android.os.Process.myUid()||(st.st_mode&0777)!=0700)
            throw new IOException("settings transaction directory differs");
        MobiMindPrivateFiles.Read intent=MobiMindPrivateFiles.read(new File(directory,"intent.json"),INTENT_LIMIT,true);
        JSONObject value=object(intent.bytes,INTENT,"id","app_uid","old_exists","old_sha256","new_exists","new_sha256","last_exists","last_sha256");
        Object uid=value.get("app_uid");
        if(!id.equals(value.get("id"))||!(uid instanceof Integer)||((Integer)uid).intValue()!=android.os.Process.myUid())
            throw new IOException("settings transaction owner differs");
        MobiMindPrivateFiles.Read old=MobiMindPrivateFiles.read(new File(directory,"previous.raw"),CONFIG_LIMIT,true);
        MobiMindPrivateFiles.Read next=MobiMindPrivateFiles.read(new File(directory,"selected.raw"),CONFIG_LIMIT,true);
        MobiMindPrivateFiles.Read last=MobiMindPrivateFiles.read(new File(directory,"previous-last.raw"),POINTER_LIMIT,true);
        hash(value,"old_sha256",old.bytes);hash(value,"new_sha256",next.bytes);hash(value,"last_sha256",last.bytes);
        Snapshot before=new Snapshot(configPath(canonical),bool(value,"old_exists"),old.bytes,null);
        Snapshot after=new Snapshot(before.path,bool(value,"new_exists"),next.bytes,null);
        Snapshot oldLast=new Snapshot(new File(root,"last.json"),bool(value,"last_exists"),last.bytes,null);
        if(!before.exists&&before.bytes.length!=0||!after.exists&&after.bytes.length!=0||!oldLast.exists&&oldLast.bytes.length!=0)
            throw new IOException("absent settings original has bytes");
        requireText(decode(before));requireText(decode(after));if(oldLast.exists)pointerId(oldLast.bytes);
        return new RuntimeConfigTransaction(canonical,root,directory,id,before,after,oldLast,recovery,intent,old,next,last);
    }
    static RuntimeConfigTransaction restore(File files)throws Exception{
        File root=settingsRoot(files,false);
        Snapshot active=read(new File(root,"pending.json"),POINTER_LIMIT);
        if(active.exists)return load(files,pointerId(active.bytes),true);
        Snapshot last=read(new File(root,"last.json"),POINTER_LIMIT);
        if(!last.exists)throw new IOException("no previous local model configuration is available");
        RuntimeConfigTransaction previous=load(files,pointerId(last.bytes),false);
        MobiMindPrivateFiles.Read commit=MobiMindPrivateFiles.read(new File(previous.directory,"committed.json"),INTENT_LIMIT,true);
        JSONObject record=new JSONObject(new String(commit.bytes,StandardCharsets.UTF_8));
        if(!"hepta.local-model-settings-commit.v1".equals(record.optString("schema"))
                ||!previous.id.equals(record.optString("id"))||!previous.after.sha().equals(record.optString("configuration_sha256")))
            throw new IOException("previous settings commit is unavailable");
        Snapshot now=current(files);
        if(!now.sameBytes(previous.after))throw new IOException("current configuration is not the saved settings result");
        last.unchanged();commit.unchangedPath();previous.originals();
        return prepare(files,previous.before.bytes,previous.before.exists);
    }
    Snapshot target(){return recoveringPending?before:after;}
    private void originals()throws Exception{
        intentRead.unchangedPath();beforeRead.unchangedPath();afterRead.unchangedPath();lastBackupRead.unchangedPath();
    }
    private Snapshot requirePending()throws Exception{
        originals();Snapshot pending=read(new File(root,"pending.json"),POINTER_LIMIT);
        if(!pending.exists||!id.equals(pointerId(pending.bytes)))throw new IOException("settings pending owner differs");
        return pending;
    }
    private static Snapshot install(Snapshot expected,Snapshot desired,String token)throws Exception{
        expected.unchanged();
        File path=expected.path,parent=path.getParentFile();
        if(desired.exists){
            File temporary=new File(parent,"runtime-settings-"+token+".new");
            MobiMindPrivateFiles.writeNew(temporary,desired.bytes);
            expected.unchanged();
            Os.rename(temporary.getPath(),path.getPath());MobiMindPrivateFiles.syncDirectory(parent);
        }else if(expected.exists){
            expected.unchanged();if(!path.delete())throw new IOException("cannot remove the owned settings file");MobiMindPrivateFiles.syncDirectory(parent);
        }
        Snapshot result=read(path,path.getName().equals("runtime-config.json")?CONFIG_LIMIT:POINTER_LIMIT);
        if(!result.sameBytes(desired))throw new IOException("atomic settings readback differs");
        result.unchanged();return result;
    }
    Snapshot apply()throws Exception{
        if(recoveringPending)throw new IOException("a pending restore cannot apply the failed selection");
        requirePending();before.unchanged();previousLast.unchanged();
        applied=install(before,after,id+"-apply");return applied;
    }
    void retainPending()throws Exception{
        originals();
        Snapshot pointerNow=read(new File(root,"pending.json"),POINTER_LIMIT);
        if(!pointerNow.exists)publishPointerIfAbsent(pointerNow.path,id);
        else if(!id.equals(pointerId(pointerNow.bytes)))throw new IOException("another settings transaction owns recovery");
    }
    Snapshot rollbackFiles()throws Exception{
        retainPending();
        Snapshot now=current(files);
        if(!now.sameBytes(before)&&!now.sameBytes(after))throw new IOException("foreign configuration change prevents rollback");
        Snapshot last=read(new File(root,"last.json"),POINTER_LIMIT);
        boolean ownLast=last.exists&&id.equals(pointerId(last.bytes));
        if(!ownLast&&!last.sameBytes(previousLast))throw new IOException("previous settings index changed");
        // Reject an unreadable/foreign index before touching the configuration.
        now.unchanged();last.unchanged();requirePending();
        Snapshot restored=now.sameBytes(before)?now:install(now,before,id+"-rollback-"+UUID.randomUUID().toString().replace("-",""));
        if(ownLast)last=install(last,previousLast,id+"-last-rollback-"+UUID.randomUUID().toString().replace("-",""));
        restored.unchanged();last.unchanged();applied=restored;return restored;
    }
    private void clearPending()throws Exception{
        Snapshot pending=requirePending();pending.unchanged();
        if(!pending.path.delete())throw new IOException("cannot remove the owned pending marker");MobiMindPrivateFiles.syncDirectory(root);
        if(MobiMindPrivateFiles.exists(pending.path))throw new IOException("settings pending marker remains");
    }
    void commit()throws Exception{
        if(recoveringPending||applied==null||!applied.sameBytes(after))throw new IOException("settings was not applied");
        requirePending();applied.unchanged();previousLast.unchanged();
        MobiMindPrivateFiles.writeNew(new File(directory,"committed.json"),new JSONObject()
                .put("schema","hepta.local-model-settings-commit.v1").put("id",id)
                .put("configuration_sha256",after.sha()).put("configuration_present",after.exists)
                .put("inference_executed",false).put("backend_qualified",false)
                .toString(2).getBytes(StandardCharsets.UTF_8));
        install(previousLast,new Snapshot(previousLast.path,true,pointer(id),null),id+"-index");
        applied.unchanged();clearPending();
    }
    void finishRollback()throws Exception{
        if(applied==null||!applied.sameBytes(before))throw new IOException("previous configuration was not restored");
        requirePending();applied.unchanged();
        File receipt=new File(directory,"restored-"+UUID.randomUUID().toString().replace("-","")+".json");
        MobiMindPrivateFiles.writeNew(receipt,new JSONObject().put("schema","hepta.local-model-settings-restore.v1")
                .put("id",id).put("configuration_sha256",before.sha()).put("configuration_present",before.exists)
                .put("exact_previous_bytes_restored",true).put("inference_executed",false)
                .toString(2).getBytes(StandardCharsets.UTF_8));
        clearPending();
    }
}
