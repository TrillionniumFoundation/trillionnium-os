package org.trillionnium.hepta.background;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Looper;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
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

/** Newly owned read-only Notes absence checker. It never signals, removes a task,
 * creates/releases a display, opens an app, injects input or writes a journal. */
public final class PublicPersonalNotesAbsenceMain {
    private PublicPersonalNotesAbsenceMain(){}
    public static void main(String[] args){
        final AtomicBoolean emitted=new AtomicBoolean();PublicPersonalNotesAbsenceRecovery.Request request=null;
        final ProfileRecoveryBootCount bootCount=new ProfileRecoveryBootCount(SystemClock::elapsedRealtime);
        JSONObject proof=null;Throwable failure=null;int boot=-1;
        try{
            need(android.os.Process.myUid()==0&&args.length==2&&"--request".equals(args[0]),"NOTES_RECOVERY_ROOT_ARGUMENTS");
            request=PublicPersonalNotesAbsenceRecovery.fromWire(args[1]);final PublicPersonalNotesAbsenceRecovery.Request bound=request;
            Thread watchdog=new Thread(()->{
                while(SystemClock.elapsedRealtime()<bound.deadline){try{Thread.sleep(Math.max(1,Math.min(100,bound.deadline-SystemClock.elapsedRealtime())));}catch(InterruptedException ignored){}}
                try{bootCount.abortForDeadline();}catch(Throwable ignored){}
                finally{failure(emitted,bound,"NOTES_RECOVERY_DEADLINE");Runtime.getRuntime().halt(70);}
            },"HeptaNotesAbsenceDeadline");watchdog.setDaemon(true);watchdog.start();
            request.requireFence(SystemClock.elapsedRealtime(),bootCount.read(request.deadline));
            if(Looper.getMainLooper()==null)Looper.prepareMainLooper();
            Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
            Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
            Context shell=system.createPackageContext("com.android.shell",0);
            JSONObject controller=RecoveryControllerIdentity.read(shell,request.ownerUid,request.deadline);
            need(PublicPersonalNotesAbsenceRecovery.same(controller,request.controller()),"NOTES_EXECUTING_INSTALLATION_CHANGED");
            Object atm=Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
            Object wm=Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
            DisplayManager dm=(DisplayManager)shell.getSystemService(Context.DISPLAY_SERVICE);
            need(atm!=null&&wm!=null&&dm!=null,"NOTES_RECOVERY_FRAMEWORK_SERVICE");
            AndroidProc proc=new AndroidProc(request);long begun=SystemClock.elapsedRealtime();
            JSONObject before=sample(request,proc,shell,atm,wm,dm,true);
            JSONObject after=sample(request,proc,shell,atm,wm,dm,false);
            need(PublicPersonalNotesAbsenceRecovery.same(controller,RecoveryControllerIdentity.read(shell,request.ownerUid,request.deadline)),"NOTES_EXECUTING_INSTALLATION_CHANGED");
            boot=bootCount.read(request.deadline);request.requireFence(SystemClock.elapsedRealtime(),boot);
            proof=new JSONObject().put("schema",request.proofSchema()).put("source",request.source())
                    .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                    .put("owner_uid",request.ownerUid).put("owner_sha256",request.ownerSha256).put("journal_sha256",request.journalSha256)
                    .put("originals_sha256",request.originalsSha256).put("original_inputs",request.inputHashes())
                    .put("public_scope_wire",request.publicScope.wire()).put("public_scope_sha256",request.publicScope.sha256)
                    .put("display_name",request.displayName).put("recorded_owned_identity",request.recordedOwnedIdentity())
                    .put("current_control_sha256",request.currentControlSha256).put("current_controller",controller)
                    .put("old_boot_count",request.oldBoot).put("current_boot_count",boot).put("lease_expires_elapsed_ms",request.expires)
                    .put("request_started_elapsed_ms",request.started).put("started_elapsed_ms",begun)
                    .put("finished_elapsed_ms",SystemClock.elapsedRealtime()).put("deadline_elapsed_ms",request.deadline)
                    .put("before",before).put("after",after).put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true)
                    .put("foreign_history_preserved",true).put("cleanup_known",true).put("automatic_resume",false)
                    .put("broker_release_response",false).put("historical_broker_release_observed",false).put("business_success",false).put("rewrites_original_task_result",false);
            PublicPersonalNotesAbsenceRecovery.validate(proof,request,SystemClock.elapsedRealtime(),boot);
            need(proof.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=PublicPersonalNotesAbsenceRecovery.MAX_OUTPUT,"NOTES_PROOF_OUTPUT_BOUND");
        }catch(Throwable failed){failure=failed;}
        // Successful publication follows the owned boot-reader close, never precedes it.
        try{bootCount.abortForDeadline();}catch(Throwable failed){if(failure==null)failure=failed;else if(failure!=failed)failure.addSuppressed(failed);}
        int exit=70;
        if(failure==null){try{need(request!=null&&proof!=null,"NOTES_PROOF_MISSING");request.requireFence(SystemClock.elapsedRealtime(),boot);
            if(emit(emitted,proof))exit=0;
        }catch(Throwable failed){failure=failed;}}
        if(failure!=null){String code=failure.getMessage();if(code==null||!code.matches("[A-Z0-9_]{1,96}"))code="NOTES_RECOVERY_UNAVAILABLE";failure(emitted,request,code);}
        System.exit(exit);
    }
    private static JSONObject sample(PublicPersonalNotesAbsenceRecovery.Request r,AndroidProc proc,Context shell,Object atm,Object wm,DisplayManager dm,boolean first)throws Exception{
        long begin=SystemClock.elapsedRealtime();JSONObject processes=first?processes(proc,r):null;
        android.content.pm.ApplicationInfo app=shell.getPackageManager().getApplicationInfo(PublicPersonalNotesAbsenceRecovery.PACKAGE,0);
        need(app!=null&&app.enabled&&app.uid==r.targetUid&&app.sourceDir!=null&&app.sourceDir.startsWith("/"),"NOTES_TARGET_INSTALLATION_CHANGED");
        JSONObject target=new JSONObject().put("package",PublicPersonalNotesAbsenceRecovery.PACKAGE).put("uid",app.uid).put("source_path",app.sourceDir).put("enabled",true);
        ProfileTaskPolicy.Snapshot snapshot=BackgroundTaskOrganizer.profileSnapshot(atm);
        JSONObject live=liveEvidence(snapshot,r);
        String raw=BackgroundTaskOrganizer.profileRecents(()->r.deadline);
        JSONObject recents=new JSONObject(PublicPersonalNotesHistory.absence(raw,r).evidence());
        JSONObject displays=displays(dm,r);
        Map<Integer,String> physical=PublicOwnGroupPhysicalReader.read(wm,dm,0,()->r.deadline);
        if(!first)processes=processes(proc,r);
        need(SystemClock.elapsedRealtime()<r.deadline,"NOTES_SAMPLE_DEADLINE");
        return new JSONObject().put("started_elapsed_ms",begin).put("finished_elapsed_ms",SystemClock.elapsedRealtime())
                .put("process",processes).put("live",live).put("recents",recents).put("displays",displays)
                .put("physical",new JSONObject().put("0",physical.get(0)).put("1",physical.get(1))).put("target_installation",target);
    }
    private static JSONObject processes(AndroidProc proc,PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{
        return ProfileRecoveryProcesses.capture(proc,android.os.Process.myPid(),r.ownerUid,r.generation,r.started,r.deadline);
    }
    private static JSONObject liveEvidence(ProfileTaskPolicy.Snapshot snapshot,PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{
        need(snapshot!=null,"NOTES_GLOBAL_CENSUS_MISSING");TreeMap<Integer,JSONObject> roots=new TreeMap<Integer,JSONObject>(),leaves=new TreeMap<Integer,JSONObject>();
        for(ProfileTaskPolicy.Root row:snapshot.roots)roots.put(row.id,new JSONObject().put("id",row.id).put("display",row.display).put("user",row.user)
                .put("activities",row.activities).put("visible",row.visible).put("base",row.base==null?JSONObject.NULL:row.base).put("top",row.top==null?JSONObject.NULL:row.top));
        for(ProfileTaskPolicy.Leaf row:snapshot.leaves.values())leaves.put(row.id,new JSONObject().put("id",row.id).put("parent",row.parent)
                .put("display",row.display).put("user",row.user).put("name",row.name));
        JSONObject out=new JSONObject().put("complete",true).put("roots",new JSONArray(roots.values())).put("leaves",new JSONArray(leaves.values()));
        PublicPersonalNotesAbsenceRecovery.requireLive(out,r);return out;
    }
    private static JSONObject displays(DisplayManager dm,PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{
        // Match the power-scope reader: getDisplays() omits disabled logical displays.
        // Read each includeDisabled Binder row directly so missing rows cannot look absent.
        Class<?> binderType=Class.forName("android.os.IBinder"),api=Class.forName("android.hardware.display.IDisplayManager");
        Object binder=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"display");
        need(binderType.isInstance(binder),"NOTES_DISPLAY_SERVICE_UNAVAILABLE");
        Object service=Class.forName("android.hardware.display.IDisplayManager$Stub").getMethod("asInterface",binderType).invoke(null,binder);
        need(service!=null,"NOTES_DISPLAY_SERVICE_UNAVAILABLE");
        java.lang.reflect.Method idsMethod=api.getMethod("getDisplayIds",boolean.class),infoMethod=api.getMethod("getDisplayInfo",int.class);
        Class<?> infoType=Class.forName("android.view.DisplayInfo");Object raw=idsMethod.invoke(service,true);
        need(raw instanceof int[],"NOTES_DISPLAY_CENSUS_BOUND");int[] all=(int[])raw;
        need(all.length>=2&&all.length<=256,"NOTES_DISPLAY_CENSUS_BOUND");TreeMap<Integer,JSONObject> rows=new TreeMap<Integer,JSONObject>();
        for(int id:all){Object info=infoMethod.invoke(service,id);
            need(id>=0&&infoType.isInstance(info)&&infoType.getField("displayId").getInt(info)==id,"NOTES_DISPLAY_UNKNOWN");
            need(rows.put(id,new JSONObject().put("id",id).put("name",infoType.getField("name").get(info))
                    .put("unique_id",infoType.getField("uniqueId").get(info)).put("flags",infoType.getField("flags").getInt(info))
                    .put("state",infoType.getField("state").getInt(info)))==null,"NOTES_DISPLAY_DUPLICATE");}
        Object ending=idsMethod.invoke(service,true);need(ending instanceof int[],"NOTES_DISPLAY_CENSUS_CHANGED");
        java.util.Set<Integer> endingIds=new java.util.TreeSet<Integer>();
        for(int id:(int[])ending)need(id>=0&&endingIds.add(id),"NOTES_DISPLAY_CENSUS_CHANGED");
        need(rows.keySet().equals(endingIds),"NOTES_DISPLAY_CENSUS_CHANGED");
        JSONObject out=new JSONObject().put("complete",true).put("rows",new JSONArray(rows.values()));PublicPersonalNotesAbsenceRecovery.requireDisplays(out,r);return out;
    }
    private static void failure(AtomicBoolean emitted,PublicPersonalNotesAbsenceRecovery.Request request,String code){try{
        emit(emitted,new JSONObject().put("schema",PublicPersonalNotesAbsenceRecovery.SCHEMA).put("request_id",request==null?JSONObject.NULL:request.requestId)
                .put("cleanup_known",false).put("error",code));}catch(Throwable ignored){System.err.println("notes_absence_recovery_output_failed");}}
    private static boolean emit(AtomicBoolean emitted,JSONObject value){if(!emitted.compareAndSet(false,true))return false;
        System.out.println(value.toString());System.out.flush();return true;}
    private static void need(boolean b,String code)throws IOException{PublicPersonalNotesAbsenceRecovery.need(b,code);}
    private static final class AndroidProc implements ProfileRecoveryProcesses.Proc {
        final PublicPersonalNotesAbsenceRecovery.Request request;
        AndroidProc(PublicPersonalNotesAbsenceRecovery.Request request){this.request=request;}
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
