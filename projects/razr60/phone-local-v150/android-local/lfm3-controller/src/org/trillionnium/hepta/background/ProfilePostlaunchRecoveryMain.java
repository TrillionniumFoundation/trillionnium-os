package org.trillionnium.hepta.background;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Looper;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.view.Display;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

/** A new root read-only process, not a broker replacement. No launch, create, remove, or input APIs. */
public final class ProfilePostlaunchRecoveryMain {
    private ProfilePostlaunchRecoveryMain(){}
    public static void main(String[] args){
        final AtomicBoolean emitted=new AtomicBoolean();ProfilePostlaunchRecovery.Request request=null;int exit=70;
        final ProfileRecoveryBootCount bootCount=new ProfileRecoveryBootCount(SystemClock::elapsedRealtime);
        try{
            ProfilePostlaunchRecovery.need(android.os.Process.myUid()==0&&args.length==2&&"--request".equals(args[0]),
                    "RECOVERY_ROOT_ARGUMENTS");
            request=ProfilePostlaunchRecovery.fromWire(args[1]);
            final ProfilePostlaunchRecovery.Request bound=request;
            Thread watchdog=new Thread(()->{
                while(SystemClock.elapsedRealtime()<bound.deadline){
                    try{Thread.sleep(Math.max(1,Math.min(100,bound.deadline-SystemClock.elapsedRealtime())));}
                    catch(InterruptedException ignored){}
                }
                try{bootCount.abortForDeadline();}
                finally{
                    failure(emitted,bound,"RECOVERY_DEADLINE");
                    // Stop the actual owned read-only child before the hard parent exit.
                    Runtime.getRuntime().halt(70);
                }
            },"HeptaProfileRecoveryDeadline");watchdog.setDaemon(true);watchdog.start();
            if(Looper.getMainLooper()==null)Looper.prepareMainLooper();
            Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
            Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
            Context shell=system.createPackageContext("com.android.shell",0);
            String[] packages=shell.getPackageManager().getPackagesForUid(request.ownerUid);
            ProfilePostlaunchRecovery.need(packages!=null&&Arrays.asList(packages).contains("org.trillionnium.hepta.local"),
                    "RECOVERY_CONTROLLER_UID");
            int boot=boot(bootCount,request);request.requireFence(SystemClock.elapsedRealtime(),boot);
            long begun=SystemClock.elapsedRealtime();
            AndroidProc proc=new AndroidProc(request);
            JSONObject processBefore=ProfileRecoveryProcesses.capture(proc,android.os.Process.myPid(),request.ownerUid,request.generation,request.started,request.deadline);
            ProfilePackages pm=new ProfilePackages(shell);
            ProfilePackages.Readback before=pm.read(request.target.profile.userId,true,request.deadline);
            ProfilePostlaunchRecovery.need(request.target.same(before.target),"RECOVERY_INSTALLATION_CHANGED");
            Object atm=Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
            ProfilePostlaunchRecovery.need(atm!=null,"RECOVERY_TASK_SERVICE");
            ProfileTaskPolicy.Snapshot live=BackgroundTaskOrganizer.profileSnapshot(atm);
            live.requireDedicatedEmpty(before.target);
            ProfileTaskPolicy.Recents recents=ProfileTaskPolicy.Recents.parse(
                    BackgroundTaskOrganizer.profileRecents(()->bound.deadline));
            recents.requireDedicatedEmpty(before.target);
            JSONObject displays=displays(shell,request);
            ProfilePackages.Readback after=pm.read(request.target.profile.userId,true,request.deadline);
            ProfilePostlaunchRecovery.need(before.target.same(after.target)&&before.activity.same(after.activity),
                    "RECOVERY_INSTALLATION_CHANGED_DURING_READ");
            JSONObject processAfter=ProfileRecoveryProcesses.capture(proc,android.os.Process.myPid(),request.ownerUid,request.generation,request.started,request.deadline);
            request.requireFence(SystemClock.elapsedRealtime(),boot(bootCount,request));
            JSONObject value=new JSONObject().put("schema",ProfilePostlaunchRecovery.SCHEMA)
                    .put("source",ProfilePostlaunchRecovery.SOURCE).put("request_id",request.requestId)
                    .put("owner_uid",request.ownerUid).put("task_id",request.taskId).put("generation",request.generation)
                    .put("owner_sha256",request.ownerSha256).put("journal_sha256",request.journalSha256)
                    .put("profile_target_wire",after.target.wire()).put("target_sha256",after.target.sha256)
                    .put("display_id",request.displayId).put("display_name",request.displayName)
                    .put("old_boot_count",request.oldBoot).put("current_boot_count",boot)
                    .put("lease_expires_elapsed_ms",request.expires).put("request_started_elapsed_ms",request.started)
                    .put("started_elapsed_ms",begun).put("finished_elapsed_ms",SystemClock.elapsedRealtime())
                    .put("deadline_elapsed_ms",request.deadline).put("boot_changed",boot!=request.oldBoot)
                    .put("no_late_create",true).put("profile_launch_attempted",true).put("identity_rechecked",true)
                    .put("live",liveEvidence(live,after.target,request.displayId)).put("recents",new JSONObject().put("complete",true)
                            .put("count",recents.rows.size()).put("bytes",recents.bytes).put("snapshot_sha256",recents.sha256)
                            .put("target_user_id",after.target.profile.userId).put("target_task_ids",new JSONArray()))
                    .put("displays",displays).put("process_before",processBefore).put("process_after",processAfter)
                    .put("cleanup_known",true).put("automatic_resume",false);
            ProfilePostlaunchRecovery.validate(value,request,SystemClock.elapsedRealtime(),boot(bootCount,request));
            emit(emitted,value);exit=0;
        }catch(Throwable failure){
            String code=failure.getMessage();
            if(code==null||!code.matches("[A-Z0-9_]{1,96}"))code="RECOVERY_UNAVAILABLE";
            failure(emitted,request,code);
        }
        System.exit(exit);
    }
    private static JSONObject liveEvidence(ProfileTaskPolicy.Snapshot snapshot,ProfileTarget target,int recordedDisplay)throws Exception{
        snapshot.requireDedicatedEmpty(target);
        for(ProfileTaskPolicy.Root row:snapshot.roots)
            ProfilePostlaunchRecovery.need(row.display!=recordedDisplay,"RECOVERY_OLD_DISPLAY_ROOT_PRESENT");
        for(ProfileTaskPolicy.Leaf row:snapshot.leaves.values())
            ProfilePostlaunchRecovery.need(row.display!=recordedDisplay,"RECOVERY_OLD_DISPLAY_LEAF_PRESENT");
        TreeMap<Integer,String> roots=new TreeMap<Integer,String>();
        TreeMap<Integer,String> leaves=new TreeMap<Integer,String>();
        for(ProfileTaskPolicy.Root row:snapshot.roots)roots.put(row.id,row.id+":"+row.display+":"+row.user+":"
                +row.activities+":"+row.visible+":"+row.base+":"+row.top);
        for(ProfileTaskPolicy.Leaf row:snapshot.leaves.values())leaves.put(row.id,row.id+":"+row.parent+":"+row.display+":"+row.user+":"+row.name);
        StringBuilder actual=new StringBuilder("roots\n");
        for(String row:roots.values())actual.append(row).append('\n');actual.append("leaves\n");
        for(String row:leaves.values())actual.append(row).append('\n');
        return new JSONObject().put("complete",true).put("root_count",roots.size()).put("leaf_count",leaves.size())
                .put("snapshot_sha256",ProfileIdentity.sha(actual.toString())).put("target_user_id",target.profile.userId)
                .put("target_task_ids",new JSONArray()).put("recorded_display_empty",true);
    }
    private static JSONObject displays(Context context,ProfilePostlaunchRecovery.Request request)throws Exception{
        DisplayManager manager=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        ProfilePostlaunchRecovery.need(manager!=null,"RECOVERY_DISPLAY_SERVICE");
        Display[] rows=manager.getDisplays();
        ProfilePostlaunchRecovery.need(rows!=null&&rows.length>0&&rows.length<=256,"RECOVERY_DISPLAY_QUERY");
        Set<Integer> ids=new HashSet<Integer>();TreeMap<Integer,String> actual=new TreeMap<Integer,String>();
        for(Display row:rows){
            ProfilePostlaunchRecovery.need(row!=null&&row.getDisplayId()>=0&&ids.add(row.getDisplayId())
                    &&row.getName()!=null&&row.getName().length()<=512,"RECOVERY_DISPLAY_IDENTITY");
            ProfilePostlaunchRecovery.need(row.getDisplayId()!=request.displayId&&!request.displayName.equals(row.getName()),"RECOVERY_OLD_DISPLAY_PRESENT");
            actual.put(row.getDisplayId(),new JSONObject().put("id",row.getDisplayId()).put("name",row.getName())
                    .put("valid",row.isValid()).toString());
        }
        ProfilePostlaunchRecovery.need(ids.contains(Display.DEFAULT_DISPLAY),"RECOVERY_DISPLAY_QUERY_INCOMPLETE");
        ProfilePostlaunchRecovery.need(manager.getDisplay(request.displayId)==null,"RECOVERY_OLD_DISPLAY_PRESENT");
        StringBuilder canonical=new StringBuilder();for(String row:actual.values())canonical.append(row).append('\n');
        return new JSONObject().put("complete",true).put("count",actual.size()).put("snapshot_sha256",ProfileIdentity.sha(canonical.toString()))
                .put("exact_name_absent",true).put("recorded_id_absent",true);
    }
    private static int boot(ProfileRecoveryBootCount reader,ProfilePostlaunchRecovery.Request request)throws Exception{
        return reader.read(request.deadline);
    }
    private static void failure(AtomicBoolean emitted,ProfilePostlaunchRecovery.Request request,String code){
        try{emit(emitted,new JSONObject().put("schema","hepta.profile-postlaunch-recovery-error.v1")
                .put("request_id",request==null?JSONObject.NULL:request.requestId).put("error",code).put("cleanup_known",false));}
        catch(Throwable ignored){System.err.println("profile_recovery_output_failed");}
    }
    private static void emit(AtomicBoolean emitted,JSONObject value){
        if(emitted.compareAndSet(false,true)){System.out.println(value.toString());System.out.flush();}
    }
    private static final class AndroidProc implements ProfileRecoveryProcesses.Proc {
        final ProfilePostlaunchRecovery.Request request;
        AndroidProc(ProfilePostlaunchRecovery.Request request){this.request=request;}
        public long now(){return SystemClock.elapsedRealtime();}
        public String[] entries()throws Exception{check();String[] rows=new File("/proc").list();
            ProfilePostlaunchRecovery.need(rows!=null,"RECOVERY_PROC_ENUMERATION");return rows;}
        public ProfileRecoveryProcesses.Directory directory(int pid)throws Exception{
            check();StructStat s;
            try{s=Os.lstat("/proc/"+pid);}
            catch(ErrnoException failure){
                if(failure.errno==OsConstants.ENOENT&&failure.getSuppressed().length==0)
                    throw new ProfileRecoveryProcesses.ProcessGone(pid,failure);
                throw failure;
            }
            ProfilePostlaunchRecovery.need(OsConstants.S_ISDIR(s.st_mode),"RECOVERY_PROC_NOT_DIRECTORY");
            return new ProfileRecoveryProcesses.Directory(s.st_uid,s.st_dev,s.st_ino);
        }
        public byte[] read(int pid,String leaf,int maximum)throws Exception{
            check();ProfilePostlaunchRecovery.need("stat".equals(leaf)||"status".equals(leaf)||"cmdline".equals(leaf),"RECOVERY_PROC_LEAF");
            FileDescriptor fd=open(pid,leaf);
            Throwable primary=null;
            try{
                ByteArrayOutputStream output=new ByteArrayOutputStream();
                StructStat before=Os.fstat(fd);ProfilePostlaunchRecovery.need(OsConstants.S_ISREG(before.st_mode),"RECOVERY_PROC_FILE_TYPE");
                byte[] buffer=new byte[4096];int count;
                while((count=Os.read(fd,buffer,0,buffer.length))>0){check();ProfilePostlaunchRecovery.need(output.size()+count<=maximum,"RECOVERY_PROC_FILE_BOUND");output.write(buffer,0,count);}
                StructStat after=Os.fstat(fd);
                ProfilePostlaunchRecovery.need(before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_uid==after.st_uid
                        &&before.st_mode==after.st_mode,"RECOVERY_PROC_FILE_CHANGED");check();return output.toByteArray();
            }catch(Exception|Error failure){primary=failure;throw failure;}
            finally{
                try{Os.close(fd);}
                catch(Exception|Error closeFailure){
                    if(primary==null)throw closeFailure;
                    if(closeFailure!=primary)primary.addSuppressed(closeFailure);
                }
            }
        }
        private FileDescriptor open(int pid,String leaf)throws Exception{
            try{return Os.open("/proc/"+pid+"/"+leaf,
                    OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);}
            catch(ErrnoException failure){
                // No FD was acquired. A missing leaf alone does not establish process exit.
                if((failure.errno==OsConstants.ENOENT||failure.errno==OsConstants.ESRCH)
                        &&failure.getSuppressed().length==0){
                    check();
                    try{Os.lstat("/proc/"+pid);}
                    catch(ErrnoException confirmation){
                        if(confirmation.errno==OsConstants.ENOENT&&confirmation.getSuppressed().length==0){
                            check();throw new ProfileRecoveryProcesses.ProcessGone(pid,failure);
                        }
                        if(confirmation!=failure)failure.addSuppressed(confirmation);
                    }
                }
                throw failure;
            }
        }
        private void check()throws IOException{
            ProfilePostlaunchRecovery.need(now()>=request.started&&now()<request.deadline,"RECOVERY_PROC_DEADLINE");
        }
    }
}
