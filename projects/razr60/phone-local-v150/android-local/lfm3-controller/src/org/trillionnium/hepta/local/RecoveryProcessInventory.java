package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.Looper;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Bounded, read-only absence evidence in the app-visible procfs namespace.
 * Foreign directory owners are not inspected. This does not prove the exit of
 * an old worker, or the absence of processes hidden even from the same UID by
 * platform policy. No package names, command lines, signals or child launches.
 */
public final class RecoveryProcessInventory {
    private static final int STAT_LIMIT=16384,STATUS_LIMIT=65536,MAX_ENTRIES=65536;
    private static final long SAMPLE_INTERVAL_MS=750;
    private RecoveryProcessInventory(){}

    public static RecoveryQuiescence.Sample capture(Context context)throws IOException{
        if(context==null||context.getApplicationInfo()==null)throw new IOException("missing application identity");
        int uid=android.os.Process.myUid(),pid=android.os.Process.myPid();
        if(uid<10000||pid<=0||context.getApplicationInfo().uid!=uid)
            throw new IOException("application UID does not match current process");
        return capture(new AndroidProc(),uid,pid);
    }

    /** Runs on a worker thread; interruption or any uncertain sample rejects recovery. */
    public static List<RecoveryQuiescence.Sample> awaitInitial(Context context)throws IOException,InterruptedException{
        if(Looper.myLooper()==Looper.getMainLooper())
            throw new IllegalStateException("recovery inventory must run off the main thread");
        List<RecoveryQuiescence.Sample> samples=new ArrayList<RecoveryQuiescence.Sample>();
        for(int i=0;i<RecoveryQuiescence.MIN_SAMPLES;i++){
            if(Thread.currentThread().isInterrupted())throw new InterruptedException("recovery inventory interrupted");
            if(i>0){
                try{Thread.sleep(SAMPLE_INTERVAL_MS);}
                catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw interrupted;}
            }
            RecoveryQuiescence.Sample sample=capture(context);
            if(sample.otherSameUidProcesses!=0)throw new IOException("another same-UID process is still visible");
            samples.add(sample);
        }
        RecoveryQuiescence.Sample first=samples.get(0);
        RecoveryQuiescence.confirm(samples,first.uid,first.pid);
        return Collections.unmodifiableList(samples);
    }

    /* Package-private seam runs the production census against controlled procfs
     * observations in host tests; the public entry point always uses /proc. */
    interface Proc {
        String[] entries()throws IOException;
        Directory directory(int pid)throws IOException;
        String read(int pid,String leaf,int maximum,int expectedUid)throws IOException;
        long elapsedMs();
    }
    static final class Directory {
        final int uid;
        final long device,inode;
        Directory(int uid,long device,long inode){this.uid=uid;this.device=device;this.inode=inode;}
        boolean same(Directory other){
            return other!=null&&uid==other.uid&&device==other.device&&inode==other.inode;
        }
    }
    private static final class Identity {
        final int pid,uid;
        final long startTicks;
        final Directory directory;
        Identity(int pid,int uid,long ticks,Directory directory){
            this.pid=pid;this.uid=uid;this.startTicks=ticks;this.directory=directory;
        }
        boolean same(Identity other){
            return other!=null&&pid==other.pid&&uid==other.uid&&startTicks==other.startTicks
                    &&directory.same(other.directory);
        }
    }

    static RecoveryQuiescence.Sample capture(Proc proc,int uid,int pid)throws IOException{
        if(proc==null||uid<10000||pid<=0)throw new IOException("invalid inventory identity");
        Directory beforeDirectory=proc.directory(pid);
        Identity before=readIdentity(proc,pid,uid,beforeDirectory);
        String[] entries=proc.entries();
        if(entries==null||entries.length==0||entries.length>MAX_ENTRIES)
            throw new IOException("process enumeration unavailable or outside bound");
        Set<Integer> seen=new HashSet<Integer>();
        boolean sawCurrent=false;
        int others=0;
        for(String name:entries){
            if(!numeric(name))continue;
            int other=parsePositiveInt(name,"process directory PID");
            if(!seen.add(other))throw new IOException("duplicate process directory");
            Directory directory=proc.directory(other);
            if(directory==null||directory.uid<0)throw new IOException("unknown process directory owner");
            if(other==pid){
                sawCurrent=true;
                if(!beforeDirectory.same(directory))throw new IOException("current process directory changed");
                continue;
            }
            if(directory.uid!=uid)continue; // Known foreign owner: never read status or cmdline.
            readIdentity(proc,other,uid,directory);
            others++;
        }
        if(!sawCurrent)throw new IOException("current process absent from enumeration");
        Identity after=readIdentity(proc,pid,uid,proc.directory(pid));
        if(!before.same(after))throw new IOException("current process identity changed during enumeration");
        long elapsed=proc.elapsedMs();
        if(elapsed<0)throw new IOException("invalid monotonic clock");
        return new RecoveryQuiescence.Sample(uid,pid,before.startTicks,elapsed,others,true);
    }

    private static Identity readIdentity(Proc proc,int pid,int uid,Directory expected)throws IOException{
        if(expected==null||expected.uid!=uid)throw new IOException("same-UID process ownership is uncertain");
        Directory first=proc.directory(pid);
        if(!expected.same(first))throw new IOException("process directory changed before reading");
        long firstTicks=startTicks(proc.read(pid,"stat",STAT_LIMIT,uid),pid);
        verifyStatus(proc.read(pid,"status",STATUS_LIMIT,uid),pid,uid);
        long lastTicks=startTicks(proc.read(pid,"stat",STAT_LIMIT,uid),pid);
        Directory last=proc.directory(pid);
        if(firstTicks!=lastTicks||!first.same(last))
            throw new IOException("process identity changed while reading");
        return new Identity(pid,uid,firstTicks,first);
    }

    private static boolean numeric(String value){
        if(value==null||value.isEmpty())return false;
        for(int i=0;i<value.length();i++)if(value.charAt(i)<'0'||value.charAt(i)>'9')return false;
        return true;
    }
    private static int parsePositiveInt(String value,String what)throws IOException{
        try{
            if(!numeric(value)||value.length()>10)throw new NumberFormatException();
            int result=Integer.parseInt(value);
            if(result<=0)throw new NumberFormatException();
            return result;
        }catch(NumberFormatException invalid){throw new IOException("invalid "+what,invalid);}
    }
    private static int parseUid(String value)throws IOException{
        try{
            if(!numeric(value)||value.length()>10)throw new NumberFormatException();
            int result=Integer.parseInt(value);
            if(result<0)throw new NumberFormatException();
            return result;
        }catch(NumberFormatException invalid){throw new IOException("invalid process UID",invalid);}
    }

    static long startTicks(String stat,int expectedPid)throws IOException{
        if(stat==null||stat.indexOf('\0')>=0||stat.length()>STAT_LIMIT)throw new IOException("invalid process stat");
        int open=stat.indexOf('('),close=stat.lastIndexOf(')');
        if(open<=0||close<=open||close+2>=stat.length()||stat.charAt(close+1)!=' ')
            throw new IOException("malformed process stat");
        if(parsePositiveInt(stat.substring(0,open).trim(),"stat PID")!=expectedPid)
            throw new IOException("stat PID mismatch");
        String[] fields=stat.substring(close+2).trim().split("\\s+");
        if(fields.length<20||fields[0].length()!=1)throw new IOException("short process stat");
        try{
            String text=fields[19]; // stat field 22; field 3 is fields[0].
            if(!numeric(text))throw new NumberFormatException();
            long ticks=Long.parseLong(text);
            if(ticks<=0)throw new NumberFormatException();
            return ticks;
        }catch(NumberFormatException invalid){throw new IOException("invalid process start ticks",invalid);}
    }

    static void verifyStatus(String status,int expectedPid,int expectedUid)throws IOException{
        if(status==null||status.indexOf('\0')>=0||status.length()>STATUS_LIMIT)
            throw new IOException("invalid process status");
        boolean gotUid=false,gotPid=false,gotTgid=false;
        for(String line:status.split("\\n")){
            if(line.startsWith("Uid:")){
                if(gotUid)throw new IOException("duplicate process UID");
                String[] values=line.substring(4).trim().split("\\s+");
                if(values.length!=4)throw new IOException("incomplete process UID tuple");
                for(String value:values)if(parseUid(value)!=expectedUid)
                    throw new IOException("process UID changed or mismatched");
                gotUid=true;
            }else if(line.startsWith("Pid:")){
                if(gotPid||parsePositiveInt(line.substring(4).trim(),"status PID")!=expectedPid)
                    throw new IOException("status PID mismatch or duplicate");
                gotPid=true;
            }else if(line.startsWith("Tgid:")){
                if(gotTgid||parsePositiveInt(line.substring(5).trim(),"status Tgid")!=expectedPid)
                    throw new IOException("status thread group mismatch or duplicate");
                gotTgid=true;
            }
        }
        if(!gotUid||!gotPid||!gotTgid)throw new IOException("process status lacks required identity");
    }

    private static final class AndroidProc implements Proc {
        public String[] entries()throws IOException{
            String[] names=new File("/proc").list();
            if(names==null)throw new IOException("cannot enumerate procfs");
            return names;
        }
        public Directory directory(int pid)throws IOException{
            try{
                StructStat stat=Os.lstat("/proc/"+pid);
                if(!OsConstants.S_ISDIR(stat.st_mode))throw new IOException("process entry is not a directory");
                return new Directory(stat.st_uid,stat.st_dev,stat.st_ino);
            }catch(ErrnoException failure){
                // Unknown owners, vanished entries and permission errors never become a quiet sample.
                throw new IOException("cannot classify process directory",failure);
            }
        }
        public String read(int pid,String leaf,int maximum,int expectedUid)throws IOException{
            if(!"stat".equals(leaf)&&!"status".equals(leaf))throw new IOException("unsupported procfs read");
            FileDescriptor fd;
            try{fd=Os.open("/proc/"+pid+"/"+leaf,OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);}
            catch(ErrnoException failure){throw new IOException("cannot open same-UID process identity",failure);}
            try(FileInputStream input=new FileInputStream(fd);ByteArrayOutputStream output=new ByteArrayOutputStream()){
                StructStat before=Os.fstat(fd);
                if(before.st_uid!=expectedUid||!OsConstants.S_ISREG(before.st_mode))
                    throw new IOException("process identity file ownership is uncertain");
                byte[] buffer=new byte[4096];
                int n;
                while((n=input.read(buffer))!=-1){
                    if(output.size()>maximum-n)throw new IOException("process identity exceeds bound");
                    output.write(buffer,0,n);
                }
                StructStat after=Os.fstat(fd);
                if(after.st_uid!=expectedUid||after.st_dev!=before.st_dev||after.st_ino!=before.st_ino
                        ||!OsConstants.S_ISREG(after.st_mode))
                    throw new IOException("process identity file changed");
                byte[] bytes=output.toByteArray();
                for(byte value:bytes)if(value==0)throw new IOException("NUL in process identity");
                return new String(bytes,StandardCharsets.UTF_8);
            }catch(ErrnoException failure){throw new IOException("cannot verify same-UID process identity",failure);}
        }
        public long elapsedMs(){return SystemClock.elapsedRealtime();}
    }
}
