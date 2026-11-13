package org.trillionnium.hepta.webhelper;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.AtomicFile;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** Private, bounded, create-only raw records; only the lease journal is mutable. */
final class EvidenceFiles {
    final File root;
    private final AtomicFile journal;
    EvidenceFiles(Context context)throws Exception{
        // Context may use a legitimate OS alias for this application's files directory.
        File appFiles=context.getFilesDir().getCanonicalFile();
        StructStat appDirectory=Os.lstat(appFiles.getPath());
        Jsons.need(OsConstants.S_ISDIR(appDirectory.st_mode)&&appDirectory.st_uid==android.os.Process.myUid(),"application files directory unsafe");
        root=new File(appFiles,"web-evidence-v1");
        if(!root.exists())Jsons.need(root.mkdir(),"evidence directory creation failed");
        StructStat directory=Os.lstat(root.getPath());
        File canonicalRoot=root.getCanonicalFile();
        Jsons.need(OsConstants.S_ISDIR(directory.st_mode)&&directory.st_uid==android.os.Process.myUid()
                &&canonicalRoot.equals(root.getAbsoluteFile())&&appFiles.equals(canonicalRoot.getParentFile()),"evidence directory unsafe");
        journal=new AtomicFile(new File(root,"lease-journal.json"));
    }
    byte[] readJournalRaw()throws Exception{
        if(!journal.getBaseFile().exists())return null;
        try(FileInputStream in=journal.openRead()){return read(in,65536);}
    }
    JSONObject readJournal()throws Exception{
        byte[] raw=readJournalRaw();
        return raw==null?null:Jsons.parseEvidence(new String(raw,StandardCharsets.UTF_8),65536);
    }
    Record preserveUnresolved(byte[] original)throws Exception{
        Jsons.need(original!=null&&original.length>0&&original.length<=65536,"complete original journal required");
        return writeBytes("unresolved-journal",Jsons.sha(original),original,true);
    }
    Record reference(JSONObject ref)throws Exception{
        Jsons.keys(ref,new java.util.TreeSet<String>(java.util.Arrays.asList("name","bytes","sha256")));
        String name=Jsons.text(ref,"name"),sha=Jsons.text(ref,"sha256");int length=Jsons.integer(ref,"bytes");
        Jsons.need(name.matches("[a-z-]{1,32}-[a-zA-Z0-9-]{1,100}\\.json")&&WebEvidenceProtocol.hex64(sha)
                &&length>0&&length<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"private record reference invalid");
        Record record=new Record(new File(root,name),length,sha);record.verify();return record;
    }
    JSONObject readObject(Record record)throws Exception{
        record.verify();try(FileInputStream in=new FileInputStream(record.path)){
            byte[] raw=read(in,record.length);Jsons.need(record.sha.equals(Jsons.sha(raw)),"record changed before parse");
            return Jsons.parseEvidence(new String(raw,StandardCharsets.UTF_8),WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
        }
    }
    void journal(JSONObject value)throws Exception{
        byte[] raw=(value.toString()+"\n").getBytes(StandardCharsets.UTF_8);Jsons.need(raw.length<=65536,"journal byte budget");
        FileOutputStream out=null;try{out=journal.startWrite();out.write(raw);out.getFD().sync();journal.finishWrite(out);}catch(Exception failure){if(out!=null)journal.failWrite(out);throw failure;}
    }
    Record write(String kind,String id,JSONObject object)throws Exception{
        return writeBytes(kind,id,(object.toString()+"\n").getBytes(StandardCharsets.UTF_8),false);
    }
    private Record writeBytes(String kind,String id,byte[] raw,boolean allowIdentical)throws Exception{
        Jsons.need(kind.matches("[a-z-]{1,32}")&&id.matches("[a-zA-Z0-9-]{1,100}"),"record name invalid");
        Jsons.need(raw.length>0&&raw.length<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"complete evidence byte budget");
        File path=new File(root,kind+"-"+id+".json");String expected=Jsons.sha(raw);
        if(allowIdentical&&path.exists()){
            Record identical=new Record(path,raw.length,expected);identical.verify();return identical;
        }
        File[] files=root.listFiles();Jsons.need(files!=null,"evidence directory unreadable");long total=0;int records=0;
        for(File file:files){StructStat s=Os.lstat(file.getPath());Jsons.need(OsConstants.S_ISREG(s.st_mode),"nonregular private record");total+=s.st_size;records++;}
        Jsons.need(records<256&&total+raw.length<=WebEvidenceProtocol.MAX_FILES_BYTES,"private evidence storage budget reached");
        FileDescriptor fd=Os.open(path.getPath(),OsConstants.O_WRONLY|OsConstants.O_CREAT|OsConstants.O_EXCL|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0600);
        try(FileOutputStream out=new FileOutputStream(fd)){out.write(raw);out.getFD().sync();}
        StructStat beforeDirectory=Os.lstat(root.getPath());
        Jsons.need(OsConstants.S_ISDIR(beforeDirectory.st_mode)&&beforeDirectory.st_uid==android.os.Process.myUid(),"evidence parent directory changed");
        // O_DIRECTORY is not in the public Android API. Verify the opened descriptor itself.
        FileDescriptor directory=Os.open(root.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try{
            StructStat openedDirectory=Os.fstat(directory);
            Jsons.need(OsConstants.S_ISDIR(openedDirectory.st_mode)&&openedDirectory.st_uid==android.os.Process.myUid()
                    &&openedDirectory.st_dev==beforeDirectory.st_dev&&openedDirectory.st_ino==beforeDirectory.st_ino,"opened evidence parent identity differs");
            Os.fsync(directory);
            StructStat afterDirectory=Os.lstat(root.getPath());
            Jsons.need(OsConstants.S_ISDIR(afterDirectory.st_mode)&&afterDirectory.st_uid==android.os.Process.myUid()
                    &&afterDirectory.st_dev==openedDirectory.st_dev&&afterDirectory.st_ino==openedDirectory.st_ino,"evidence parent replaced during fsync");
        }finally{Os.close(directory);}
        Record result=new Record(path,raw.length,expected);result.verify();return result;
    }
    static final class Record {
        final File path;final int length;final String sha;
        Record(File path,int length,String sha){this.path=path;this.length=length;this.sha=sha;}
        JSONObject reference()throws Exception{return new JSONObject().put("name",path.getName()).put("bytes",length).put("sha256",sha);}
        void verify()throws Exception{
            StructStat before=Os.lstat(path.getPath());Jsons.need(OsConstants.S_ISREG(before.st_mode)&&before.st_nlink==1&&before.st_size==length,"raw record identity differs");
            try(FileInputStream in=new FileInputStream(path)){byte[] raw=read(in,length);Jsons.need(raw.length==length&&sha.equals(Jsons.sha(raw)),"raw record bytes differ");}
            StructStat after=Os.lstat(path.getPath());Jsons.need(before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_size==after.st_size&&before.st_mtime==after.st_mtime,"raw record changed");
        }
        ParcelFileDescriptor openReadOnly()throws Exception{
            verify();ParcelFileDescriptor fd=ParcelFileDescriptor.open(path,ParcelFileDescriptor.MODE_READ_ONLY);
            Jsons.need(fd.getStatSize()==length,"read-only descriptor size differs");return fd;
        }
    }
    private static byte[] read(FileInputStream in,int maximum)throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int n;
        while((n=in.read(buffer))!=-1){Jsons.need(out.size()+n<=maximum,"private record read budget");out.write(buffer,0,n);}return out.toByteArray();
    }
}
