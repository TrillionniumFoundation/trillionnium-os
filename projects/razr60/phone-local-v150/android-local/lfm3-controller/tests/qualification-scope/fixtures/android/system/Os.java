package android.system;
import java.io.*;import java.nio.file.*;import java.util.*;
/** Host filesystem surrogate. Directory fsync/Android UID authorization are not simulated claims. */
public final class Os {
 private static final Map<FileDescriptor,Open> OPEN=new IdentityHashMap<FileDescriptor,Open>();
 private static final class Open {final Path path;final RandomAccessFile file;Open(Path p,RandomAccessFile f){path=p;file=f;}}
 public static StructStat lstat(String s)throws Exception{Path p=Paths.get(s);if(!Files.exists(p,LinkOption.NOFOLLOW_LINKS))throw new ErrnoException("lstat",2);Map<String,Object> a=Files.readAttributes(p,"unix:*",LinkOption.NOFOLLOW_LINKS);StructStat r=new StructStat();r.st_dev=((Number)a.get("dev")).longValue();r.st_ino=((Number)a.get("ino")).longValue();r.st_size=((Number)a.get("size")).longValue();r.st_nlink=((Number)a.get("nlink")).longValue();r.st_uid=((Number)a.get("uid")).intValue();r.st_mode=((Number)a.get("mode")).intValue();r.st_mtime=((java.nio.file.attribute.FileTime)a.get("lastModifiedTime")).toMillis()/1000;r.st_ctime=((java.nio.file.attribute.FileTime)a.get("ctime")).toMillis()/1000;return r;}
 public static StructStat fstat(FileDescriptor fd)throws Exception{return lstat(OPEN.get(fd).path.toString());}
 public static FileDescriptor open(String s,int flags,int mode)throws Exception{Path p=Paths.get(s);if(Files.isSymbolicLink(p))throw new ErrnoException("nofollow",40);if((flags&OsConstants.O_EXCL)!=0&&Files.exists(p))throw new ErrnoException("exists",17);
  if((flags&OsConstants.O_CREAT)!=0){Files.createFile(p);chmod(s,mode);}if(!Files.exists(p))throw new ErrnoException("open",2);
  if(Files.isDirectory(p)){FileDescriptor fd=new FileDescriptor();OPEN.put(fd,new Open(p,null));return fd;}
  RandomAccessFile file=new RandomAccessFile(s,(flags&OsConstants.O_WRONLY)!=0?"rw":"r");FileDescriptor fd=file.getFD();OPEN.put(fd,new Open(p,file));return fd;}
 public static void close(FileDescriptor fd)throws Exception{Open o=OPEN.remove(fd);if(o!=null&&o.file!=null)o.file.close();}
 public static void chmod(String s,int mode)throws Exception{Files.setAttribute(Paths.get(s),"unix:mode",mode);}
 public static void mkdir(String s,int mode)throws Exception{Files.createDirectory(Paths.get(s));chmod(s,mode);}
 public static int write(FileDescriptor fd,byte[] b,int p,int n)throws Exception{OPEN.get(fd).file.write(b,p,n);return n;}
 public static void fsync(FileDescriptor fd)throws Exception{if(fd.valid())fd.sync();}
}
