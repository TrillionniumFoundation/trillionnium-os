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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

/** A newly owned, bounded, read-only root checker. It cannot create a display,
 * start/stop an app, remove tasks, change permissions, send input or retire a lease. */
public final class PublicProfileRecoveryMain {
    private PublicProfileRecoveryMain(){}
    public static void main(String[] args){
        final AtomicBoolean emitted=new AtomicBoolean();PublicProfileAbsenceRecovery.Request request=null;int exit=70;
        final ProfileRecoveryBootCount bootCount=new ProfileRecoveryBootCount(SystemClock::elapsedRealtime);
        try{
            need(android.os.Process.myUid()==0&&args.length==2&&"--request".equals(args[0]),"PUBLIC_RECOVERY_ROOT_ARGUMENTS");
            request=PublicProfileAbsenceRecovery.fromWire(args[1]);final PublicProfileAbsenceRecovery.Request bound=request;
            Thread watchdog=new Thread(()->{
                while(SystemClock.elapsedRealtime()<bound.deadline){try{Thread.sleep(Math.max(1,Math.min(100,bound.deadline-SystemClock.elapsedRealtime())));}catch(InterruptedException ignored){}}
                try{bootCount.abortForDeadline();}finally{failure(emitted,bound,"PUBLIC_RECOVERY_DEADLINE");Runtime.getRuntime().halt(70);}
            },"HeptaPublicRecoveryDeadline");watchdog.setDaemon(true);watchdog.start();
            // Settings.Global from this root-created Context is deliberately not used.
            // The boot-count adapter owns the fixed cmd child and proves its exit/EOF.
            request.requireFence(SystemClock.elapsedRealtime(),bootCount.read(request.deadline));
            if(Looper.getMainLooper()==null)Looper.prepareMainLooper();
            Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
            Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
            Context shell=system.createPackageContext("com.android.shell",0);
            JSONObject controller=RecoveryControllerIdentity.read(shell,request.ownerUid,request.deadline);
            need(PublicProfileAbsenceRecovery.same(controller,request.controller()),"PUBLIC_RECOVERY_EXECUTING_INSTALLATION_CHANGED");
            Object atm=Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
            Object wm=Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
            DisplayManager dm=(DisplayManager)shell.getSystemService(Context.DISPLAY_SERVICE);
            need(atm!=null&&wm!=null&&dm!=null,"PUBLIC_RECOVERY_FRAMEWORK_SERVICE");
            ProfilePackages pm=new ProfilePackages(shell);AndroidProc proc=new AndroidProc(request);
            long begun=SystemClock.elapsedRealtime();
            JSONObject before=sample(request,proc,pm,atm,wm,dm,true);
            JSONObject after=sample(request,proc,pm,atm,wm,dm,false);
            need(PublicProfileAbsenceRecovery.same(controller,RecoveryControllerIdentity.read(shell,request.ownerUid,request.deadline)),
                    "PUBLIC_RECOVERY_EXECUTING_INSTALLATION_CHANGED");
            int boot=bootCount.read(request.deadline);request.requireFence(SystemClock.elapsedRealtime(),boot);
            JSONObject proof=new JSONObject().put("schema",request.proofSchema()).put("source",request.source())
                    .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                    .put("owner_uid",request.ownerUid).put("owner_sha256",request.ownerSha256).put("journal_sha256",request.journalSha256)
                    .put("originals_sha256",request.originalsSha256).put("original_inputs",request.inputHashes())
                    .put("public_scope_wire",request.publicScope.wire()).put("public_scope_sha256",request.publicScope.sha256)
                    .put("profile_target_wire",request.target.wire()).put("target_sha256",request.target.sha256).put("display_name",request.displayName)
                    .put("old_boot_count",request.oldBoot).put("current_boot_count",boot).put("lease_expires_elapsed_ms",request.expires)
                    .put("request_started_elapsed_ms",request.started).put("started_elapsed_ms",begun)
                    .put("finished_elapsed_ms",SystemClock.elapsedRealtime()).put("deadline_elapsed_ms",request.deadline)
                    .put("current_controller",controller).put("before",before).put("after",after)
                    .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true)
                    .put("historical_creation_unknown",!request.postlaunch).put("business_dispatch_absent_in_original_receipts",!request.postlaunch)
                    .put("foreign_dormant_history_preserved",true)
                    .put("cleanup_known",true).put("automatic_resume",false).put("broker_release_response",false);
            if(request.postlaunch)proof.put("profile_bootstrap_dispatched",true).put("historical_broker_release_observed",true)
                    .put("model_action_dispatch_absent_in_original_receipts",true).put("recorded_owned_identity",request.recordedOwnedIdentity());
            PublicProfileAbsenceRecovery.validate(proof,request,SystemClock.elapsedRealtime(),boot);
            emit(emitted,proof);exit=0;
        }catch(Throwable failed){String code=failed.getMessage();if(code==null||!code.matches("[A-Z0-9_]{1,96}"))code="PUBLIC_RECOVERY_UNAVAILABLE";failure(emitted,request,code);}
        System.exit(exit);
    }
    private static JSONObject sample(PublicProfileAbsenceRecovery.Request r,AndroidProc proc,ProfilePackages pm,Object atm,Object wm,DisplayManager dm,boolean first)throws Exception{
        long begin=SystemClock.elapsedRealtime();JSONObject processes=first?processes(proc,r):null;
        ProfilePackages.Readback installation=pm.read(r.target.profile.userId,true,r.deadline);
        need(r.target.same(installation.target),"PUBLIC_RECOVERY_TARGET_INSTALLATION_CHANGED");
        ProfileTaskPolicy.Snapshot live=BackgroundTaskOrganizer.profileSnapshot(atm);live.requireDedicatedEmpty(r.target);r.requireRecordedLiveAbsent(live);
        String recentRaw=BackgroundTaskOrganizer.profileRecents(()->r.deadline);
        PublicProfileRecentHistory.Snapshot recents=PublicProfileRecentHistory.absence(recentRaw,r.target);r.requireRecordedRecentsAbsent(recentRaw);
        JSONObject displays=displays(dm,r);
        Map<Integer,String> physical=PublicOwnGroupPhysicalReader.read(wm,dm,r.target.profile.userId,()->r.deadline);
        if(!first)processes=processes(proc,r);
        need(SystemClock.elapsedRealtime()<r.deadline,"PUBLIC_RECOVERY_SAMPLE_DEADLINE");
        return new JSONObject().put("started_elapsed_ms",begin).put("finished_elapsed_ms",SystemClock.elapsedRealtime())
                .put("process",processes).put("live",liveEvidence(live,r))
                .put("recents",new JSONObject(recents.evidence()))
                .put("displays",displays).put("physical",new JSONObject().put("0",physical.get(0)).put("1",physical.get(1)))
                .put("target_sha256",installation.target.sha256);
    }
    private static JSONObject processes(AndroidProc proc,PublicProfileAbsenceRecovery.Request r)throws Exception{
        return ProfileRecoveryProcesses.capture(proc,android.os.Process.myPid(),r.ownerUid,r.generation,r.started,r.deadline);
    }
    private static JSONObject liveEvidence(ProfileTaskPolicy.Snapshot snapshot,PublicProfileAbsenceRecovery.Request request)throws Exception{
        ProfileTarget target=request.target;
        snapshot.requireDedicatedEmpty(target);TreeMap<Integer,String> roots=new TreeMap<Integer,String>(),leaves=new TreeMap<Integer,String>();
        for(ProfileTaskPolicy.Root row:snapshot.roots)roots.put(row.id,row.id+":"+row.display+":"+row.user+":"+row.activities+":"+row.visible+":"+row.base+":"+row.top);
        for(ProfileTaskPolicy.Leaf row:snapshot.leaves.values())leaves.put(row.id,row.id+":"+row.parent+":"+row.display+":"+row.user+":"+row.name);
        StringBuilder raw=new StringBuilder("roots\n");for(String row:roots.values())raw.append(row).append('\n');raw.append("leaves\n");for(String row:leaves.values())raw.append(row).append('\n');
        JSONObject result=new JSONObject().put("complete",true).put("root_count",roots.size()).put("leaf_count",leaves.size())
                .put("snapshot_sha256",ProfileIdentity.sha(raw.toString())).put("target_user_id",target.profile.userId).put("target_task_ids",new JSONArray());
        if(request.postlaunch){request.requireRecordedLiveAbsent(snapshot);
            result.put("all_task_ids",new JSONArray(new java.util.TreeSet<Integer>(snapshot.allIds)))
                    .put("recorded_owned_ids_absent",true).put("recorded_display_empty",true);}
        return result;
    }
    private static JSONObject displays(DisplayManager dm,PublicProfileAbsenceRecovery.Request r)throws Exception{
        Display[] all=dm.getDisplays();need(all!=null&&all.length>=2&&all.length<=256,"PUBLIC_RECOVERY_DISPLAY_CENSUS");
        Set<Integer> ids=new HashSet<Integer>();TreeMap<Integer,String> facts=new TreeMap<Integer,String>();
        for(Display display:all){need(display!=null&&display.isValid(),"PUBLIC_RECOVERY_DISPLAY_UNKNOWN");int id=display.getDisplayId();String name=display.getName();
            need(id>=0&&ids.add(id)&&name!=null&&name.length()<=512&&name.indexOf('\0')<0,"PUBLIC_RECOVERY_DISPLAY_IDENTITY");
            need(!r.displayName.equals(name),"PUBLIC_RECOVERY_OWNED_DISPLAY_PRESENT");
            need(!r.postlaunch||id!=r.displayId,"PUBLIC_POSTLAUNCH_DISPLAY_ID_REUSED");
            String unique=(String)Display.class.getMethod("getUniqueId").invoke(display);
            need(unique!=null&&unique.length()>0&&unique.length()<=1024,"PUBLIC_RECOVERY_DISPLAY_UNIQUE_ID");
            facts.put(id,id+":"+name+":"+unique+":"+display.getFlags()+":"+display.getState());}
        need(ids.contains(0)&&ids.contains(1),"PUBLIC_RECOVERY_PHYSICAL_DISPLAYS_MISSING");StringBuilder raw=new StringBuilder();for(String row:facts.values())raw.append(row).append('\n');
        JSONObject result=new JSONObject().put("complete",true).put("count",facts.size()).put("snapshot_sha256",ProfileIdentity.sha(raw.toString())).put("exact_name_absent",true);
        if(r.postlaunch)result.put("recorded_id_absent",true);return result;
    }
    private static void failure(AtomicBoolean emitted,PublicProfileAbsenceRecovery.Request request,String code){try{
        emit(emitted,new JSONObject().put("schema",request==null?PublicProfileAbsenceRecovery.SCHEMA:request.proofSchema()).put("request_id",request==null?JSONObject.NULL:request.requestId)
                .put("cleanup_known",false).put("error",code));}catch(Throwable ignored){System.err.println("public_profile_recovery_output_failed");}}
    private static void emit(AtomicBoolean emitted,JSONObject value){if(emitted.compareAndSet(false,true)){System.out.println(value.toString());System.out.flush();}}
    private static void need(boolean b,String code)throws IOException{PublicProfileAbsenceRecovery.need(b,code);}
    private static final class AndroidProc implements ProfileRecoveryProcesses.Proc {
        final PublicProfileAbsenceRecovery.Request request;
        AndroidProc(PublicProfileAbsenceRecovery.Request request){this.request=request;}
        public long now(){return SystemClock.elapsedRealtime();}
        public String[] entries()throws Exception{check();String[] rows=new File("/proc").list();
            ProfilePrelaunchRecovery.need(rows!=null,"RECOVERY_PROC_ENUMERATION");return rows;}
        public ProfileRecoveryProcesses.Directory directory(int pid)throws Exception{
            check();StructStat s;
            try{s=Os.lstat("/proc/"+pid);}
            catch(ErrnoException failure){
                if(failure.errno==OsConstants.ENOENT&&failure.getSuppressed().length==0)
                    throw new ProfileRecoveryProcesses.ProcessGone(pid,failure);
                throw failure;
            }
            ProfilePrelaunchRecovery.need(OsConstants.S_ISDIR(s.st_mode),"RECOVERY_PROC_NOT_DIRECTORY");
            return new ProfileRecoveryProcesses.Directory(s.st_uid,s.st_dev,s.st_ino);
        }
        public byte[] read(int pid,String leaf,int maximum)throws Exception{
            check();ProfilePrelaunchRecovery.need("stat".equals(leaf)||"status".equals(leaf)||"cmdline".equals(leaf),"RECOVERY_PROC_LEAF");
            FileDescriptor fd=open(pid,leaf);
            Throwable primary=null;
            try{
                ByteArrayOutputStream output=new ByteArrayOutputStream();
                StructStat before=Os.fstat(fd);ProfilePrelaunchRecovery.need(OsConstants.S_ISREG(before.st_mode),"RECOVERY_PROC_FILE_TYPE");
                byte[] buffer=new byte[4096];int count;
                while((count=Os.read(fd,buffer,0,buffer.length))>0){check();ProfilePrelaunchRecovery.need(output.size()+count<=maximum,"RECOVERY_PROC_FILE_BOUND");output.write(buffer,0,count);}
                StructStat after=Os.fstat(fd);
                ProfilePrelaunchRecovery.need(before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_uid==after.st_uid
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
            ProfilePrelaunchRecovery.need(now()>=request.started&&now()<request.deadline,"RECOVERY_PROC_DEADLINE");
        }
    }
}
