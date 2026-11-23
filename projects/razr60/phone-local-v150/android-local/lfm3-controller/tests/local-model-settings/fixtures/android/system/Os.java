package android.system;
import java.io.*;import java.nio.file.*;import java.nio.file.attribute.FileTime;import java.util.*;
/** Real host temp-file IO and rename. Android UID and FD metadata/directory fsync are declared surrogates.
 * No model process, Android framework, signals, ADB or phone is reachable from this fixture. */
public final class Os {
 private Os(){}
 private static final class Open {final Path path;final RandomAccessFile file;Open(Path p,RandomAccessFile f){path=p;file=f;}}
 private static final Map<FileDescriptor,Open> OPEN=Collections.synchronizedMap(new IdentityHashMap<FileDescriptor,Open>());
 public static final List<String> events=Collections.synchronizedList(new ArrayList<String>());
 public static String faultEvent,faultNeedle,hookEvent,hookNeedle,uidOverridePath;public static int remaining;public static boolean halt,triggered;public static Runnable hook;
 public static void reset(){faultEvent=faultNeedle=hookEvent=hookNeedle=uidOverridePath=null;remaining=0;halt=triggered=false;hook=null;events.clear();}
 public static void fail(String event,String needle,int count,boolean crash){faultEvent=event;faultNeedle=needle;remaining=count;halt=crash;triggered=false;}
 private static void hit(String event,String path)throws ErrnoException{
  events.add(event+" "+path);
  if(hook!=null&&event.equals(hookEvent)&&path.contains(hookNeedle)){Runnable once=hook;hook=null;once.run();}
  if(event.equals(faultEvent)&&path.contains(faultNeedle)&&--remaining==0){triggered=true;faultEvent=null;if(halt)Runtime.getRuntime().halt(86);throw new ErrnoException("injected "+event,5);}
 }
 private static ErrnoException failure(String op,Exception e){return e instanceof ErrnoException?(ErrnoException)e:new ErrnoException(op,e instanceof NoSuchFileException?2:5,e);}
 public static StructStat lstat(String s)throws ErrnoException{
  try{hit("BEFORE_LSTAT",s);Path p=Paths.get(s);Map<String,Object>a=Files.readAttributes(p,"unix:*",LinkOption.NOFOLLOW_LINKS);StructStat r=new StructStat();
   r.st_dev=((Number)a.get("dev")).longValue();r.st_ino=((Number)a.get("ino")).longValue();r.st_size=((Number)a.get("size")).longValue();r.st_nlink=((Number)a.get("nlink")).longValue();
   r.st_uid=((Number)a.get("uid")).intValue();if(r.st_uid==Integer.parseInt(System.getProperty("hepta.fixture.host_uid")))r.st_uid=10481;
   if(s.equals(uidOverridePath))r.st_uid=10482;r.st_gid=((Number)a.get("gid")).intValue();r.st_mode=((Number)a.get("mode")).intValue();
   r.st_mtime=((FileTime)a.get("lastModifiedTime")).toMillis()/1000;r.st_ctime=((FileTime)a.get("ctime")).toMillis()/1000;return r;
  }catch(Exception e){throw failure("lstat",e);}
 }
 public static StructStat fstat(FileDescriptor fd)throws ErrnoException{Open x=OPEN.get(fd);if(x==null)throw new ErrnoException("untracked fd",9);return lstat(x.path.toString());}
 public static FileDescriptor open(String s,int flags,int mode)throws ErrnoException{
  try{hit("BEFORE_OPEN",s);Path p=Paths.get(s);if(Files.isSymbolicLink(p))throw new ErrnoException("nofollow",40);
   if((flags&OsConstants.O_CREAT)!=0){Files.createFile(p);chmod(s,mode);hit("AFTER_CREATE",s);}
   if(!Files.exists(p,LinkOption.NOFOLLOW_LINKS))throw new ErrnoException("open",2);
   if(Files.isDirectory(p)){FileDescriptor fd=new FileDescriptor();OPEN.put(fd,new Open(p,null));return fd;}
   RandomAccessFile f=new RandomAccessFile(s,(flags&OsConstants.O_WRONLY)!=0?"rw":"r");FileDescriptor fd=f.getFD();OPEN.put(fd,new Open(p,f));return fd;
  }catch(Exception e){throw failure("open",e);}
 }
 public static void close(FileDescriptor fd)throws ErrnoException{try{Open x=OPEN.remove(fd);if(x!=null&&x.file!=null)x.file.close();}catch(Exception e){throw failure("close",e);}}
 public static void chmod(String s,int mode)throws ErrnoException{try{Files.setAttribute(Paths.get(s),"unix:mode",mode);}catch(Exception e){throw failure("chmod",e);}}
 public static void mkdir(String s,int mode)throws ErrnoException{try{Files.createDirectory(Paths.get(s));chmod(s,mode);}catch(Exception e){throw failure("mkdir",e);}}
 public static int read(FileDescriptor fd,byte[] b,int start,int length)throws ErrnoException{try{Open x=OPEN.get(fd);hit("BEFORE_READ",x.path.toString());int n=x.file.read(b,start,length);hit("AFTER_READ",x.path.toString());return n<0?0:n;}catch(Exception e){throw failure("read",e);}}
 public static int write(FileDescriptor fd,byte[] b,int start,int length)throws ErrnoException{
  try{Open x=OPEN.get(fd);String s=x.path.toString();hit("BEFORE_WRITE",s);
   if("PARTIAL_WRITE".equals(faultEvent)&&s.contains(faultNeedle)){int count=Math.max(1,length/2);x.file.write(b,start,count);hit("PARTIAL_WRITE",s);return count;}
   x.file.write(b,start,length);hit("AFTER_WRITE",s);return length;
  }catch(Exception e){throw failure("write",e);}
 }
 public static void fsync(FileDescriptor fd)throws ErrnoException{try{Open x=OPEN.get(fd);String s=x.path.toString();hit("BEFORE_FSYNC",s);if(x.file!=null)fd.sync();else events.add("DIRECTORY_FSYNC_SURROGATE "+s);hit("AFTER_FSYNC",s);}catch(Exception e){throw failure("fsync",e);}}
 public static void rename(String from,String to)throws ErrnoException{try{hit("BEFORE_RENAME",to);Files.move(Paths.get(from),Paths.get(to),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);hit("AFTER_RENAME",to);}catch(Exception e){throw failure("rename",e);}}
}
