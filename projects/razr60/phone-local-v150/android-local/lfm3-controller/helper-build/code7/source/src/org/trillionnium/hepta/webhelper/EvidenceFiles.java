package org.trillionnium.hepta.webhelper;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.AtomicFile;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
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
    interface TransferGuard { void requireCurrent()throws Exception; }
    /** The authenticated controller has already persisted and re-read all three
     * original records. The request nonce/hash is durable in our lease journal
     * before this method is scheduled. Only its exact capture leaf can retire. */
    void acknowledgeCapture(JSONObject request,String requestRaw,JSONObject binding,TransferGuard guard)throws Exception{
        org.trillionnium.hepta.webprotocol.WebCaptureAcknowledgement.requireRequest(request,binding);
        Jsons.need(guard!=null,"live capture transfer guard required");
        Jsons.need(org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(request).equals(
                org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(Jsons.parse(requestRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES))),
                "capture transfer parsed request differs from exact wire bytes");
        requireDurableCaptureAcknowledgement(request,requestRaw,binding,guard);
        JSONObject proof=request.getJSONObject("durable_acknowledgement");
        String nonce=Jsons.text(request,"capture_request_nonce");
        File path=new File(root,"capture-"+nonce+".json");
        StructStat parent=Os.lstat(root.getPath());
        Jsons.need(root.equals(root.getCanonicalFile())&&OsConstants.S_ISDIR(parent.st_mode)
                &&parent.st_uid==android.os.Process.myUid(),"capture transfer parent is unsafe");
        StructStat before=Os.lstat(path.getPath());
        Jsons.need(OsConstants.S_ISREG(before.st_mode)&&before.st_uid==android.os.Process.myUid()
                &&before.st_nlink==1&&(before.st_mode&077)==0&&before.st_size==Jsons.number(proof,"raw_bytes"),
                "capture transfer leaf metadata differs");
        byte[] raw;
        FileDescriptor descriptor=Os.open(path.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try(FileInputStream in=new FileInputStream(descriptor)){
            StructStat opened=Os.fstat(descriptor);Jsons.need(sameTransferFile(before,opened),"capture transfer opened another file");
            raw=read(in,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
            Jsons.need(sameTransferFile(opened,Os.fstat(descriptor)),"capture transfer changed while reading");
        }
        JSONObject record=Jsons.parseCaptureEvidence(strictTransferUtf8(raw),WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
        JSONObject originalRequest=Jsons.parse(Jsons.text(record,"request_json_utf8"),WebEvidenceProtocol.MAX_REQUEST_BYTES);
        org.trillionnium.hepta.webprotocol.WebCaptureAcknowledgement.requireOriginal(request,binding,raw,record,originalRequest);
        guard.requireCurrent();
        StructStat currentParent=Os.lstat(root.getPath()),currentFile=Os.lstat(path.getPath());
        Jsons.need(sameTransferFile(before,currentFile)&&OsConstants.S_ISDIR(currentParent.st_mode)
                &&currentParent.st_uid==android.os.Process.myUid()&&currentParent.st_dev==parent.st_dev&&currentParent.st_ino==parent.st_ino,
                "capture transfer path or parent changed before unlink");
        // No wildcard, journal, ARM, close, diagnostic, failed or unknown record
        // is eligible. Failure after unlink remains an unknown acknowledgement;
        // the independently durable controller copy is never removed.
        Jsons.need(path.delete(),"capture transfer unlink failed");
        FileDescriptor directory=Os.open(root.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try{
            StructStat opened=Os.fstat(directory);
            Jsons.need(OsConstants.S_ISDIR(opened.st_mode)&&opened.st_uid==android.os.Process.myUid()
                    &&opened.st_dev==parent.st_dev&&opened.st_ino==parent.st_ino,"capture transfer opened another parent");
            Os.fsync(directory);
            StructStat after=Os.lstat(root.getPath());
            Jsons.need(OsConstants.S_ISDIR(after.st_mode)&&after.st_uid==android.os.Process.myUid()
                    &&after.st_dev==opened.st_dev&&after.st_ino==opened.st_ino,"capture transfer parent replaced during fsync");
        }finally{Os.close(directory);}
        try{Os.lstat(path.getPath());throw new IllegalStateException("capture transfer unlink did not remove the leaf");}
        catch(android.system.ErrnoException absent){Jsons.need(absent.errno==OsConstants.ENOENT,"capture transfer absence is unknown");}
    }
    private void requireDurableCaptureAcknowledgement(JSONObject request,String requestRaw,JSONObject binding,TransferGuard guard)throws Exception{
        guard.requireCurrent();
        File path=journal.getBaseFile();
        Jsons.need(!transferExists(new File(path.getPath()+".new"))&&!transferExists(new File(path.getPath()+".bak")),
                "capture transfer journal has an unfinished AtomicFile sidecar");
        StructStat parent=Os.lstat(root.getPath()),before=Os.lstat(path.getPath());
        Jsons.need(root.equals(root.getCanonicalFile())&&OsConstants.S_ISDIR(parent.st_mode)
                &&parent.st_uid==android.os.Process.myUid(),"capture transfer journal parent is unsafe");
        Jsons.need(OsConstants.S_ISREG(before.st_mode)&&before.st_uid==android.os.Process.myUid()
                &&before.st_nlink==1&&(before.st_mode&077)==0&&before.st_size>0&&before.st_size<=65536,
                "capture transfer journal is not one direct private file");
        FileDescriptor descriptor=Os.open(path.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try(FileInputStream in=new FileInputStream(descriptor)){
            StructStat opened=Os.fstat(descriptor);Jsons.need(sameTransferFile(before,opened),"capture transfer journal descriptor differs");
            byte[] bytes=read(in,65536);
            JSONObject record=Jsons.parseEvidence(strictTransferUtf8(bytes),65536);
            Jsons.need(WebEvidenceProtocol.JOURNAL_SCHEMA.equals(Jsons.text(record,"schema"))
                    &&"active".equals(Jsons.text(record,"state"))
                    &&WebEvidenceBinding.sha256(binding).equals(Jsons.text(record,"binding_sha256"))
                    &&org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(binding).equals(
                            org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(record.getJSONObject("binding")))
                    &&Jsons.sha(requestRaw).equals(record.getJSONObject("consumed_requests").getString(
                            Jsons.text(request,"request_nonce"))),"capture ACK was not durably consumed by this exact lease");
            Jsons.need(bytes.length==before.st_size&&sameTransferFile(opened,Os.fstat(descriptor)),
                    "capture transfer journal changed during readback");
            Os.fsync(descriptor);
            Jsons.need(sameTransferFile(before,Os.lstat(path.getPath())),"capture transfer journal path changed after sync");
        }
        FileDescriptor directory=Os.open(root.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try{
            StructStat opened=Os.fstat(directory);
            Jsons.need(OsConstants.S_ISDIR(opened.st_mode)&&opened.st_uid==android.os.Process.myUid()
                    &&opened.st_dev==parent.st_dev&&opened.st_ino==parent.st_ino,"capture transfer journal parent descriptor differs");
            Os.fsync(directory);
            StructStat after=Os.lstat(root.getPath());
            Jsons.need(OsConstants.S_ISDIR(after.st_mode)&&after.st_uid==android.os.Process.myUid()
                    &&after.st_dev==opened.st_dev&&after.st_ino==opened.st_ino,"capture transfer journal parent changed during sync");
        }finally{Os.close(directory);}
        Jsons.need(!transferExists(new File(path.getPath()+".new"))&&!transferExists(new File(path.getPath()+".bak")),
                "capture transfer journal sidecar appeared after readback");
        guard.requireCurrent();
    }
    private static boolean transferExists(File path)throws Exception{
        try{Os.lstat(path.getPath());return true;}
        catch(android.system.ErrnoException absent){if(absent.errno==OsConstants.ENOENT)return false;throw absent;}
    }
    private static String strictTransferUtf8(byte[] bytes)throws Exception{
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString();
    }
    private static boolean sameTransferFile(StructStat a,StructStat b){
        return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid
                &&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink&&a.st_size==b.st_size&&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;
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
