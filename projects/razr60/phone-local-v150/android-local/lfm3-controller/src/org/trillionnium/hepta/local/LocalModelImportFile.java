package org.trillionnium.hepta.local;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.json.JSONObject;

/** One private file transaction. Atomic link publication never replaces an existing destination.
 * The temporary second link is removed and its absence fsynced before the model slot is released.
 * A durable marker lets a later, explicitly requested import remove only its exact interrupted temp.
 */
final class LocalModelImportFile {
    static final String PENDING="local-model-import.pending.json";
    private static final String SCHEMA="hepta.local-model-import-pending.v1";
    interface Pins {Pin named(String id);}
    static final class Pin {
        final String id,directory,filename,sha256;final long bytes;
        Pin(String id,String directory,String filename,long bytes,String sha256){
            if(id==null||!id.matches("[a-zA-Z0-9._/-]{1,160}")
                    ||!("model".equals(directory)||"gui-owl-model".equals(directory)||"lfm3-vl-model".equals(directory))
                    ||filename==null||!filename.matches("[a-zA-Z0-9._-]+[.]gguf")
                    ||bytes<=0||sha256==null||!sha256.matches("[0-9a-f]{64}"))
                throw new IllegalArgumentException("固定模型文件参数无效");
            this.id=id;this.directory=directory;this.filename=filename;this.bytes=bytes;this.sha256=sha256;
        }
    }
    private LocalModelImportFile(){}
    static boolean pending(File files)throws Exception{return MobiMindPrivateFiles.exists(new File(files,PENDING));}
    private static File directory(File files,Pin pin)throws Exception{
        if(!files.getAbsoluteFile().equals(files.getCanonicalFile()))throw new IOException("模型目录不可用");
        File directory=new File(files,pin.directory);
        MobiMindPrivateFiles.directory(directory,false);
        if(!directory.getCanonicalFile().getParentFile().equals(files))throw new IOException("模型目录已变化");
        return directory;
    }
    private static StructStat regular(File file,long maximum)throws Exception{
        if(!file.getAbsoluteFile().equals(file.getCanonicalFile()))throw new IOException("模型文件不能是链接");
        StructStat value=Os.lstat(file.getPath());
        if(!OsConstants.S_ISREG(value.st_mode)||value.st_uid!=android.os.Process.myUid()
                ||(value.st_mode&07777)!=0600||value.st_size<0||value.st_size>maximum)
            throw new IOException("模型文件的归属、大小或权限不符");
        return value;
    }
    private static boolean inode(StructStat a,StructStat b){
        return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid
                &&a.st_mode==b.st_mode;
    }
    private static boolean unchanged(StructStat a,StructStat b){
        return inode(a,b)&&a.st_size==b.st_size&&a.st_nlink==b.st_nlink
                &&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;
    }
    static boolean ready(File files,Pin pin,ModelImportStream.Cancellation cancelled)throws Exception{
        File target=new File(directory(files,pin),pin.filename);
        if(!MobiMindPrivateFiles.exists(target))return false;
        StructStat before=regular(target,pin.bytes);
        if(before.st_nlink!=1||before.st_size!=pin.bytes)throw new IOException("同名模型文件已存在但未通过核验；原文件已保留");
        ModelImportStream.check(cancelled);
        FileDescriptor fd=Os.open(target.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try(FileInputStream input=new FileInputStream(fd)){
            if(!unchanged(before,Os.fstat(fd)))throw new IOException("原模型文件身份已变化");
            ModelImportStream.copy(input,new OutputStream(){
                @Override public void write(int value){}
                @Override public void write(byte[] data,int offset,int count){}
            },pin.bytes,pin.sha256,cancelled,null);
            if(!unchanged(before,Os.fstat(fd)))throw new IOException("原模型文件在核验期间发生变化");
        }
        ModelImportStream.check(cancelled);
        if(!unchanged(before,regular(target,pin.bytes)))throw new IOException("原模型文件在核验期间发生变化");
        return true;
    }
    /** Never deletes a destination, including after an interrupted publication. */
    static void recover(File files,Pins pins)throws Exception{
        File pending=new File(files,PENDING);
        if(!MobiMindPrivateFiles.exists(pending))return;
        MobiMindPrivateFiles.Read held=MobiMindPrivateFiles.read(pending,4096,true);
        JSONObject value=new JSONObject(new String(held.bytes,StandardCharsets.UTF_8));
        if(value.length()!=6||!SCHEMA.equals(value.get("schema"))||!(value.get("token") instanceof String)
                ||!value.getString("token").matches("[0-9a-f]{32}")
                ||!(value.get("uid") instanceof Integer)||value.getInt("uid")!=android.os.Process.myUid()
                ||!(value.get("asset") instanceof String)||!((value.get("bytes") instanceof Integer)||(value.get("bytes") instanceof Long))
                ||!(value.get("sha256") instanceof String))throw new IOException("上次导入记录无法核验");
        Pin pin=pins.named(value.getString("asset"));
        if(value.getLong("bytes")!=pin.bytes||!pin.sha256.equals(value.getString("sha256")))
            throw new IOException("上次导入的模型版本不符");
        File dir=directory(files,pin),target=new File(dir,pin.filename);
        File temporary=new File(dir,".hepta-import-"+value.getString("token")+".partial");
        removeTemporary(temporary,target,pin,null);
        held.unchangedPath();Os.unlink(pending.getPath());MobiMindPrivateFiles.syncDirectory(files);
    }
    private static void removeTemporary(File temporary,File target,Pin pin,StructStat owned)throws Exception{
        if(MobiMindPrivateFiles.exists(temporary)){
            StructStat actual=regular(temporary,pin.bytes);
            if(owned!=null&&!inode(owned,actual))throw new IOException("导入临时文件身份已变化");
            if(actual.st_nlink!=1){
                if(actual.st_nlink!=2||!MobiMindPrivateFiles.exists(target)
                        ||!inode(actual,regular(target,pin.bytes)))
                    throw new IOException("导入临时文件仍有未知引用");
            }
            Os.unlink(temporary.getPath());MobiMindPrivateFiles.syncDirectory(temporary.getParentFile());
        }
        if(MobiMindPrivateFiles.exists(temporary))throw new IOException("导入临时文件尚未清理");
    }
    static Stage begin(File files,Pin pin)throws Exception{
        File dir=directory(files,pin),target=new File(dir,pin.filename);
        if(MobiMindPrivateFiles.exists(target))throw new IOException("同名模型已经存在，原文件已保留");
        if(pending(files))throw new IOException("上次导入尚未清理");
        String token=UUID.randomUUID().toString().replace("-","");
        File marker=new File(files,PENDING),temp=new File(dir,".hepta-import-"+token+".partial");
        JSONObject value=new JSONObject().put("schema",SCHEMA).put("asset",pin.id).put("token",token)
                .put("uid",android.os.Process.myUid()).put("bytes",pin.bytes).put("sha256",pin.sha256);
        MobiMindPrivateFiles.writeNew(marker,value.toString().getBytes(StandardCharsets.UTF_8));
        return new Stage(files,dir,target,temp,pin,MobiMindPrivateFiles.read(marker,4096,true));
    }
    static final class Stage {
        final File files,directory,target,temporary;final Pin pin;
        final MobiMindPrivateFiles.Read marker;
        private StructStat owned,complete;private boolean copied,published,finished,markerRemoved;
        Stage(File files,File directory,File target,File temporary,Pin pin,MobiMindPrivateFiles.Read marker){
            this.files=files;this.directory=directory;this.target=target;this.temporary=temporary;this.pin=pin;this.marker=marker;
        }
        void copy(InputStream input,ModelImportStream.Cancellation cancelled,ModelImportStream.Progress progress)throws Exception{
            if(copied||owned!=null||finished)throw new IOException("本次导入已开始");
            marker.unchangedPath();ModelImportStream.check(cancelled);
            FileDescriptor fd=Os.open(temporary.getPath(),OsConstants.O_WRONLY|OsConstants.O_CREAT
                    |OsConstants.O_EXCL|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0600);
            try(FileOutputStream output=new FileOutputStream(fd)){
                owned=Os.fstat(fd);
                if(!inode(owned,regular(temporary,pin.bytes))||owned.st_nlink!=1||owned.st_size!=0)
                    throw new IOException("新建导入文件身份不符");
                ModelImportStream.copy(input,output,pin.bytes,pin.sha256,cancelled,progress);
                output.flush();Os.fsync(fd);ModelImportStream.check(cancelled);
                complete=Os.fstat(fd);
                if(!inode(owned,complete)||complete.st_nlink!=1||complete.st_size!=pin.bytes
                        ||!unchanged(complete,regular(temporary,pin.bytes)))throw new IOException("导入文件在写入期间发生变化");
                copied=true;
            }
        }
        void publish(ModelImportStream.Cancellation cancelled)throws Exception{
            if(!copied||finished||published)throw new IOException("导入文件尚未完整核验");
            ModelImportStream.check(cancelled);marker.unchangedPath();
            if(!unchanged(complete,regular(temporary,pin.bytes)))throw new IOException("待导入文件身份已变化");
            // link() is atomic and refuses EEXIST. rename() would overwrite a newly arrived good model.
            Os.link(temporary.getPath(),target.getPath());published=true;
            StructStat targetStat=regular(target,pin.bytes),tempStat=regular(temporary,pin.bytes);
            if(!inode(complete,targetStat)||!inode(targetStat,tempStat)
                    ||targetStat.st_size!=pin.bytes||targetStat.st_nlink!=2)throw new IOException("模型发布身份不符");
            removeTemporary(temporary,target,pin,owned);
            StructStat finalStat=regular(target,pin.bytes);
            if(!inode(complete,finalStat)||finalStat.st_size!=pin.bytes||finalStat.st_nlink!=1)
                throw new IOException("模型发布尚未完成");
            MobiMindPrivateFiles.syncDirectory(directory);
            finishMarker();finished=true;
        }
        void abort()throws Exception{
            if(finished)return;
            // If exclusive create failed, a pre-existing path is not ours to remove.
            if(owned==null&&MobiMindPrivateFiles.exists(temporary))throw new IOException("临时文件创建归属未确认");
            removeTemporary(temporary,target,pin,owned);
            if(published){
                StructStat result=regular(target,pin.bytes);
                if(!inode(complete,result)||result.st_size!=pin.bytes||result.st_nlink!=1)
                    throw new IOException("已发布模型的完整状态未确认");
            }
            finishMarker();finished=true;
        }
        private void finishMarker()throws Exception{
            if(!markerRemoved){marker.unchangedPath();Os.unlink(marker.path.getPath());markerRemoved=true;}
            MobiMindPrivateFiles.syncDirectory(files);
            if(MobiMindPrivateFiles.exists(marker.path))throw new IOException("导入记录尚未完成");
        }
    }
}

