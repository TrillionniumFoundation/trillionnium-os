#!/usr/bin/env python3
"""Compile actual private-files class and byte-exact AndroidProc block with explicit Os test doubles."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
p=argparse.ArgumentParser();p.add_argument("--out",required=True);p.add_argument("--source-root",type=Path,default=Path(__file__).resolve().parents[2])
p.add_argument("--jdk-bin",type=Path,required=True,help="Host JDK bin containing javac/java")
p.add_argument("--compile-only",action="store_true",help="Packaging compile only; no Java test execution")
a=p.parse_args()
root=a.source_root.resolve();tests=Path(__file__).resolve().parent;out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
fixture=out/"fixture";fixture.mkdir();classes=out/"classes";classes.mkdir()
jdk=a.jdk_bin.resolve()
main=root/"src/org/trillionnium/hepta/background/ProfileRecoveryMain.java"
private=root/"src/org/trillionnium/hepta/local/MobiMindPrivateFiles.java"
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(main)=="069970c4c1d9350e709d18b7b2da4e204178727efbf1c0894066a02384a4b79f"
assert sha(private)=="9bf20793a50815d82d4a9447f5aaa290ab3dafe506f21179f6bf28b560d0ff9e"
processes=root/"src/org/trillionnium/hepta/background/ProfileRecoveryProcesses.java"
assert sha(processes)=="14f735150e48c1f2dc985e3a805ae1fde30a0ea828a5d83959c78328b03c2757"
process_text=processes.read_text()
gone_start=process_text.index("    static final class ProcessGone")
gone_block=process_text[gone_start:process_text.index("\n    private static final class SelfPin",gone_start)]
text=main.read_text();block=text[text.index("    private static final class AndroidProc"):text.rfind("\n}")]
assert block.endswith("    }") and "while((count=Os.read(" in block
sources=[]
def put(relative,value):
    path=fixture/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value);sources.append(path)
put("android/os/SystemClock.java","package android.os; public final class SystemClock { public static long value; public static long elapsedRealtime(){return value;} }\n")
put("android/os/Process.java","package android.os; public final class Process { public static int myUid(){return 10481;} }\n")
put("android/system/ErrnoException.java",'''package android.system;
public final class ErrnoException extends Exception {
    private static final long serialVersionUID=1L;
    public final int errno;
    public ErrnoException(String function,int errno){super(function+" errno "+errno);this.errno=errno;}
}
''')
put("android/system/StructStat.java",'''package android.system;
public final class StructStat {
    public long st_dev,st_ino,st_size,st_nlink,st_mtime,st_ctime;
    public int st_uid,st_mode;
}
''')
put("android/system/OsConstants.java",'''package android.system;
public final class OsConstants {
    public static final int O_RDONLY=0,O_WRONLY=1,O_CREAT=64,O_EXCL=128,O_NOFOLLOW=131072,O_CLOEXEC=524288,ENOENT=2,ESRCH=3,EACCES=13,EMFILE=24;
    public static boolean S_ISREG(int mode){return (mode&0170000)==0100000;}
    public static boolean S_ISDIR(int mode){return (mode&0170000)==0040000;}
}
''')
put("android/system/Os.java",'''package android.system;
import java.io.FileDescriptor;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
public final class Os {
    public static int opens,closes,reads,fstats,eofZero,ownerUid,openAttempts,directoryCalls;
    public static long reportedSize,advanceClockAfterRead,advanceClockAfterOpenFailure,advanceClockAfterLstat;
    public static boolean changeIdentity,changePathIdentity;
    public static ErrnoException readFailure,statFailure,closeFailure,openFailure,directoryFailure;
    private static byte[] data;private static int offset;
    private static final Set<FileDescriptor> live=Collections.newSetFromMap(new IdentityHashMap<FileDescriptor,Boolean>());
    public static void reset(byte[] bytes){
        if(!live.isEmpty())throw new AssertionError("test left an open descriptor");
        data=bytes.clone();offset=0;opens=closes=reads=fstats=eofZero=openAttempts=directoryCalls=0;ownerUid=10481;
        reportedSize=data.length;advanceClockAfterRead=advanceClockAfterOpenFailure=advanceClockAfterLstat=0;changeIdentity=changePathIdentity=false;
        readFailure=statFailure=closeFailure=openFailure=directoryFailure=null;
    }
    private static StructStat metadata(boolean changed){
        StructStat s=new StructStat();s.st_dev=changed?2:1;s.st_ino=42;s.st_size=reportedSize;
        s.st_uid=ownerUid;s.st_mode=0100600;s.st_nlink=1;s.st_mtime=3;s.st_ctime=4;return s;
    }
    private static void require(FileDescriptor fd){if(!live.contains(fd))throw new AssertionError("unowned or closed FD");}
    public static FileDescriptor open(String path,int flags,int mode)throws ErrnoException{
        openAttempts++;
        if(openFailure!=null){
            if(advanceClockAfterOpenFailure!=0)android.os.SystemClock.value=advanceClockAfterOpenFailure;
            throw openFailure;
        }
        opens++;FileDescriptor fd=new FileDescriptor();live.add(fd);return fd;
    }
    public static StructStat fstat(FileDescriptor fd)throws ErrnoException{
        require(fd);fstats++;if(statFailure!=null)throw statFailure;return metadata(changeIdentity&&fstats>1);
    }
    public static StructStat lstat(String path)throws ErrnoException{
        directoryCalls++;
        if(advanceClockAfterLstat!=0)android.os.SystemClock.value=advanceClockAfterLstat;
        if(directoryFailure!=null)throw directoryFailure;
        StructStat s=metadata(changePathIdentity);if(path.startsWith("/proc/"))s.st_mode=0040500;return s;
    }
    public static int read(FileDescriptor fd,byte[] buffer,int at,int count)throws ErrnoException{
        require(fd);reads++;if(readFailure!=null)throw readFailure;
        if(offset==data.length){eofZero++;return 0;}
        int n=Math.min(count,data.length-offset);System.arraycopy(data,offset,buffer,at,n);offset+=n;
        if(advanceClockAfterRead!=0)android.os.SystemClock.value=advanceClockAfterRead;return n;
    }
    public static void close(FileDescriptor fd)throws ErrnoException{
        require(fd);closes++;live.remove(fd);if(closeFailure!=null)throw closeFailure;
    }
    public static void mkdir(String path,int mode)throws ErrnoException{throw new AssertionError("write outside read gate");}
    public static void chmod(String path,int mode)throws ErrnoException{throw new AssertionError("write outside read gate");}
    public static int write(FileDescriptor fd,byte[] bytes,int at,int count)throws ErrnoException{throw new AssertionError("write outside read gate");}
    public static void fsync(FileDescriptor fd)throws ErrnoException{throw new AssertionError("write outside read gate");}
}
''')
put("org/trillionnium/hepta/background/ProfilePrelaunchRecovery.java",'''package org.trillionnium.hepta.background;
import java.io.IOException;
final class ProfilePrelaunchRecovery {
    static final class Request {final long started,deadline;Request(long started,long deadline){this.started=started;this.deadline=deadline;}}
    static void need(boolean condition,String reason)throws IOException{if(!condition)throw new IOException(reason);}
}
''')
put("org/trillionnium/hepta/background/ProfileRecoveryProcesses.java",'''package org.trillionnium.hepta.background;
import java.io.IOException;
final class ProfileRecoveryProcesses {
    static final class Directory {Directory(int uid,long dev,long ino){}}
    interface Proc {long now();String[] entries()throws Exception;Directory directory(int pid)throws Exception;byte[] read(int pid,String leaf,int maximum)throws Exception;}
'''+gone_block+"\n}\n")
put("org/trillionnium/hepta/background/AndroidProcProjection.java",'''package org.trillionnium.hepta.background;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
public final class AndroidProcProjection {
    public static byte[] read(long started,long deadline,int maximum)throws Exception{
        return new AndroidProc(new ProfilePrelaunchRecovery.Request(started,deadline)).read(123,"stat",maximum);
    }
    public static ProfileRecoveryProcesses.Directory directory(long started,long deadline)throws Exception{
        return new AndroidProc(new ProfilePrelaunchRecovery.Request(started,deadline)).directory(123);
    }
'''+block+"\n}\n")
put("org/trillionnium/hepta/local/PrivateFilesAccess.java",'''package org.trillionnium.hepta.local;
import java.io.File;
public final class PrivateFilesAccess {
    public static byte[] read(int maximum)throws Exception{
        return MobiMindPrivateFiles.read(new File("/tmp/hepta-fd-owned-fixture"),maximum,true).bytes;
    }
}
''')
test=tests/"FdOwnershipHostTest.java"
adapter=tests/"ProcErrnoAdapterHostTest.java"
sources.extend([private,test,adapter])
result={"schema":"hepta.fd-ownership-host-run.v1","phone_contacted":False,"android_runtime":False,"tests_executed":not a.compile_only,
 "actual_private_files_full_class_sha256":sha(private),"actual_main_sha256":sha(main),"actual_processes_sha256":sha(processes),
 "process_gone_block_sha256":hashlib.sha256(gone_block.encode()).hexdigest(),
 "android_proc_block_sha256":hashlib.sha256(block.encode()).hexdigest(),"android_proc_block_byte_exact":True,
 "projection_scope":"Only AndroidProc block is actual; framework, request DTO and Proc interface are explicit host doubles.",
 "sources":[{"path":str(s),"sha256":sha(s)} for s in sources],"commands":[]}
commands=[
 ("compile",[str(jdk/"javac"),"--release","8","-Xlint:all,-options","-Werror","-proc:none","-d",str(classes)]+[str(s) for s in sources],30),
 ("test",[str(jdk/"java"),"-cp",str(classes),"org.trillionnium.hepta.background.FdOwnershipHostTest"],10),
 ("adapter-test",[str(jdk/"java"),"-cp",str(classes),"org.trillionnium.hepta.background.ProcErrnoAdapterHostTest"],10)]
if a.compile_only:commands=commands[:1]
for name,cmd,limit in commands:
    begun=time.monotonic();run=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=limit,check=False)
    (out/(name+".stdout")).write_bytes(run.stdout);(out/(name+".stderr")).write_bytes(run.stderr)
    result["commands"].append({"stage":name,"argv":cmd,"exit_code":run.returncode,"elapsed_s":round(time.monotonic()-begun,6),
      "stdout_sha256":sha(out/(name+".stdout")),"stderr_sha256":sha(out/(name+".stderr"))})
    if run.returncode:result["passed"]=False;break
    if name=="test":result["test"]=json.loads(run.stdout)
    if name=="adapter-test":result["adapter_test"]=json.loads(run.stdout)
else:result["passed"]=True
receipt=out/"RESULT.json";receipt.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
print(json.dumps({"result":str(receipt),"sha256":sha(receipt),"passed":result["passed"],"test":result.get("test"),"adapter_test":result.get("adapter_test")}))
raise SystemExit(0 if result["passed"] else 1)
