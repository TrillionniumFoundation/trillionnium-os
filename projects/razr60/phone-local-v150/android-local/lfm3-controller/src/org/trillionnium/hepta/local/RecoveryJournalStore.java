package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Narrow private-file adapter; never visits task directories, native receipts or model files. */
final class RecoveryJournalStore implements RecoveryJournalTransaction.Store {
    private static final int LIMIT=65536;
    private final File root;
    private final int uid;
    RecoveryJournalStore(Context context)throws Exception{
        root=context.getFilesDir().getCanonicalFile();uid=Process.myUid();checkDirectory(root,false);
    }
    final class Lock implements AutoCloseable {
        private FileOutputStream stream;
        private FileLock held;
        Lock(FileOutputStream stream,FileLock held){this.stream=stream;this.held=held;}
        public synchronized void close()throws IOException{
            IOException failure=null;
            if(held!=null){try{held.release();}catch(IOException e){failure=e;}held=null;}
            if(stream!=null){try{stream.close();}catch(IOException e){if(failure==null)failure=e;}stream=null;}
            if(failure!=null)throw failure;
        }
    }
    Lock lock()throws Exception{
        File f=new File(root,"control-session.recovery.lock");
        if(!f.getCanonicalFile().equals(f))throw new IOException("recovery lock is not private");
        FileDescriptor fd=Os.open(f.getPath(),OsConstants.O_RDWR|OsConstants.O_CREAT|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0600);
        FileOutputStream stream=null;
        try{
            checkRegular(Os.fstat(fd));stream=new FileOutputStream(fd);
            FileLock lock=stream.getChannel().tryLock();
            if(lock==null)throw new IOException("another recovery transaction owns the store");
            return new Lock(stream,lock);
        }catch(Exception e){if(stream!=null)stream.close();else Os.close(fd);throw e;}
    }
    public byte[] read(String name)throws Exception{
        File f=path(name);StructStat before;
        try{before=Os.lstat(f.getPath());}catch(ErrnoException e){if(e.errno==OsConstants.ENOENT)return null;throw e;}
        checkRegular(before);
        FileDescriptor fd=Os.open(f.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try{
            StructStat opened=Os.fstat(fd);checkRegular(opened);sameIdentity(before,opened);
            ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];
            for(;;){int n=Os.read(fd,buffer,0,buffer.length);if(n==0)break;if(n<0||out.size()+n>LIMIT)throw new IOException("oversized private record");out.write(buffer,0,n);}
            StructStat after=Os.fstat(fd);sameIdentity(opened,after);sameIdentity(after,Os.lstat(f.getPath()));
            if(out.size()!=after.st_size)throw new IOException("private record changed length");return out.toByteArray();
        }finally{Os.close(fd);}
    }
    public List<String> pendingBarriers()throws Exception{
        checkDirectory(root,false);String[] names=root.list();if(names==null)throw new IOException("cannot enumerate recovery barriers");
        List<String> result=new ArrayList<String>();
        for(String name:names)if(name.startsWith(RecoveryJournalTransaction.PENDING_PREFIX))result.add(name);
        return result;
    }
    public void create(String name,byte[] bytes)throws Exception{
        if(bytes==null||bytes.length>LIMIT)throw new IOException("invalid recovery record length");
        File f=path(name);ensureParent(f.getParentFile());
        FileDescriptor fd=Os.open(f.getPath(),OsConstants.O_WRONLY|OsConstants.O_CREAT|OsConstants.O_EXCL
                |OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0600);
        try{
            checkRegular(Os.fstat(fd));int offset=0;
            while(offset<bytes.length){int n=Os.write(fd,bytes,offset,bytes.length-offset);if(n<=0)throw new IOException("incomplete private write");offset+=n;}
            Os.fsync(fd);
        }finally{Os.close(fd);}
        syncDirectory(f.getParentFile());
        if(!Arrays.equals(bytes,read(name)))throw new IOException("private write did not verify");
    }
    public void replaceActive(byte[] expected,byte[] replacement,String transactionId)throws Exception{
        if(!Arrays.equals(expected,read(RecoveryJournalTransaction.ACTIVE)))throw new IOException("active journal changed before publish");
        String temporary="session-acknowledgements/"+transactionId+"/PUBLISH.tmp";
        create(temporary,replacement);
        if(!Arrays.equals(expected,read(RecoveryJournalTransaction.ACTIVE)))throw new IOException("active journal changed during publish");
        File from=path(temporary),to=path(RecoveryJournalTransaction.ACTIVE);
        Os.rename(from.getPath(),to.getPath());syncDirectory(root);syncDirectory(from.getParentFile());
        if(!Arrays.equals(replacement,read(RecoveryJournalTransaction.ACTIVE)))throw new IOException("new journal publication did not verify");
    }
    public void removeIfEqual(String name,byte[] expected)throws Exception{
        byte[] current=read(name);if(!Arrays.equals(current,expected))throw new IOException("barrier changed before removal");
        if(current==null)return;
        File f=path(name);Os.remove(f.getPath());syncDirectory(f.getParentFile());
        if(read(name)!=null)throw new IOException("barrier remained after removal");
    }
    public void sync()throws Exception{syncDirectory(root);}

    private File path(String name)throws Exception{
        boolean fixed=RecoveryJournalTransaction.ACTIVE.equals(name)||RecoveryJournalTransaction.LATCH.equals(name)
                ||(RecoveryJournalTransaction.ACTIVE+".bak").equals(name)||(RecoveryJournalTransaction.ACTIVE+".new").equals(name);
        boolean barrier=name!=null&&name.matches("control-session\\.recovery-pending-[0-9a-f]{32}\\.record");
        boolean artifact=name!=null&&name.matches("session-acknowledgements/[0-9a-f]{32}/(?:[A-Z-]+\\.(?:record|json)|PUBLISH\\.tmp|original-[0-9]{3}\\.bin)");
        if(!fixed&&!barrier&&!artifact)throw new IOException("unsupported recovery path");
        File f=new File(root,name);
        if(!f.getCanonicalFile().equals(f))throw new IOException("recovery path contains an alias");
        File parent=f.getParentFile();while(!parent.equals(root)){
            try{checkDirectory(parent,true);}catch(ErrnoException e){if(e.errno!=OsConstants.ENOENT)throw e;}
            parent=parent.getParentFile();if(parent==null)throw new IOException("recovery path escaped private root");
        }
        checkDirectory(root,false);return f;
    }
    private void ensureParent(File directory)throws Exception{
        if(directory.equals(root)){checkDirectory(root,false);return;}
        ensureParent(directory.getParentFile());
        try{Os.mkdir(directory.getPath(),0700);syncDirectory(directory.getParentFile());}
        catch(ErrnoException e){if(e.errno!=OsConstants.EEXIST)throw e;}
        checkDirectory(directory,true);
    }
    private void checkDirectory(File directory,boolean exactMode)throws Exception{
        if(!directory.getCanonicalFile().equals(directory))throw new IOException("private directory contains an alias");
        StructStat s=Os.lstat(directory.getPath());
        if(!OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=uid||(exactMode&&(s.st_mode&0777)!=0700))
            throw new IOException("unowned or unsafe recovery directory");
    }
    private void checkRegular(StructStat s)throws IOException{
        if(!OsConstants.S_ISREG(s.st_mode)||s.st_uid!=uid||s.st_nlink!=1||(s.st_mode&0777)!=0600||s.st_size<0||s.st_size>LIMIT)
            throw new IOException("unowned, aliased or oversized recovery record");
    }
    private static void sameIdentity(StructStat a,StructStat b)throws IOException{
        if(a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_uid!=b.st_uid||a.st_mode!=b.st_mode
                ||a.st_nlink!=b.st_nlink||a.st_size!=b.st_size||a.st_mtime!=b.st_mtime||a.st_ctime!=b.st_ctime)
            throw new IOException("private record identity changed");
    }
    private void syncDirectory(File directory)throws Exception{
        checkDirectory(directory,!directory.equals(root));
        FileDescriptor fd=Os.open(directory.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try{StructStat s=Os.fstat(fd);if(!OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=uid)throw new IOException("unowned directory descriptor");Os.fsync(fd);}
        finally{Os.close(fd);}
    }
}
