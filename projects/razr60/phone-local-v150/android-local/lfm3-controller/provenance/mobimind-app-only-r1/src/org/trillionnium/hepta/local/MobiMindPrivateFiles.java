package org.trillionnium.hepta.local;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;

/** Small, bounded private inputs and installed runtime files; model weights stay native-owned. */
final class MobiMindPrivateFiles {
    private MobiMindPrivateFiles() {}
    static boolean exists(File path)throws Exception{
        try{Os.lstat(path.getPath());return true;}
        catch(android.system.ErrnoException failure){if(failure.errno==OsConstants.ENOENT)return false;throw failure;}
    }
    static File directory(File path,boolean fresh)throws Exception{
        if(!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new IOException("directory must be canonical");
        if(fresh||!exists(path))Os.mkdir(path.getPath(),0700);
        StructStat st=Os.lstat(path.getPath());
        if(!OsConstants.S_ISDIR(st.st_mode)||st.st_uid!=android.os.Process.myUid())throw new IOException("directory must be app-owned");
        Os.chmod(path.getPath(),0700);return path;
    }
    static final class Read {
        final File path;final byte[] bytes;final StructStat stat;
        Read(File path,byte[] bytes,StructStat stat){this.path=path;this.bytes=bytes;this.stat=stat;}
        void unchangedPath()throws Exception{if(!same(stat,Os.lstat(path.getPath())))throw new IOException("input path changed");}
    }
    static Read read(File path,int maximum,boolean owned)throws Exception{
        if(maximum<1||!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new IOException("canonical bounded file required");
        FileDescriptor fd=Os.open(path.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        FileInputStream in=null;
        try{
            StructStat before=Os.fstat(fd);
            if(!OsConstants.S_ISREG(before.st_mode)||before.st_size<0||before.st_size>maximum
                    ||(owned&&(before.st_uid!=android.os.Process.myUid()||before.st_nlink!=1||(before.st_mode&0777)!=0600)))
                throw new IOException("file ownership/type/size/mode mismatch: "+path.getName());
            in=new FileInputStream(fd);ByteArrayOutputStream data=new ByteArrayOutputStream();byte[] buffer=new byte[65536];int n;
            while((n=in.read(buffer))!=-1){if(data.size()+n>maximum)throw new IOException("file grew beyond bound");data.write(buffer,0,n);}
            if(data.size()!=before.st_size||!same(before,Os.fstat(fd))||!same(before,Os.lstat(path.getPath())))throw new IOException("file changed during read");
            return new Read(path,data.toByteArray(),before);
        }finally{if(in!=null)in.close();else Os.close(fd);}
    }
    static void writeNew(File path,byte[] bytes)throws Exception{
        if(!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new IOException("canonical new file required");
        FileDescriptor fd=Os.open(path.getPath(),OsConstants.O_WRONLY|OsConstants.O_CREAT|OsConstants.O_EXCL
                |OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0600);
        try{int at=0;while(at<bytes.length){int n=Os.write(fd,bytes,at,bytes.length-at);if(n<=0)throw new IOException("short private write");at+=n;}Os.fsync(fd);}
        finally{Os.close(fd);}
        syncDirectory(path.getParentFile());
    }
    static void syncDirectory(File path)throws Exception{
        FileDescriptor fd=Os.open(path.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try{Os.fsync(fd);}finally{Os.close(fd);}
    }
    private static boolean same(StructStat a,StructStat b){return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size
        &&a.st_uid==b.st_uid&&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink&&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;}
}
