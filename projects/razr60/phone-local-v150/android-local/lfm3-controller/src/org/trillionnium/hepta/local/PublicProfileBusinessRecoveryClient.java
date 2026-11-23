package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Explicit cleanup of an expired public profile lease after completed worker work.
 * This client does not grant a tool, acknowledge the interrupted session, or rewrite
 * its business result. Only its newly owned checker can create the opaque receipt. */
final class PublicProfileBusinessRecoveryClient {
    private static final AtomicReference<Flight> ACTIVE=new AtomicReference<Flight>();
    private static final int SUMMARY_LIMIT=65536;
    private PublicProfileBusinessRecoveryClient(){}

    static boolean workPending(){return ACTIVE.get()!=null;}
    /** Cleanup callbacks remain pending until the real owned process and reader end. */
    static void afterOwnedCheckerDrain(Runnable completion){
        Flight flight=ACTIVE.get();if(flight==null)completion.run();else flight.whenDrained(completion);
    }
    /** Main-thread bounded routing only. Full records and authority are checked on
     * the worker. A malformed archived origin is never projected to zero steps. */
    static boolean hasBusinessOrigin(Context context)throws Exception{
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);
        File lease=new File(root.path,PublicProfileBusinessAbsenceRecovery.JOURNAL);
        if(!MobiMindPrivateFiles.exists(lease))return false;
        JSONObject journal=object(MobiMindPrivateFiles.read(lease,16384,true).bytes);
        if(!Boolean.TRUE.equals(journal.opt("public_own_group_experimental"))||!(journal.opt("display_id") instanceof Number)
                ||number(journal,"display_id")<=1)return false;
        JSONObject current=object(MobiMindPrivateFiles.read(new File(root.path,PublicProfileBusinessAbsenceRecovery.CONTROL),SUMMARY_LIMIT,true).bytes);
        String origin=originPath(current);JSONObject summary=PublicProfileBusinessAbsenceRecovery.CONTROL.equals(origin)?current:
                object(MobiMindPrivateFiles.read(new File(root.path,origin),SUMMARY_LIMIT,true).bytes);
        root.unchanged(context);
        if(!string(journal,"task_id").equals(string(summary,"task_id")))throw new IOException("业务恢复的当前摘要与原租约任务不同");
        Object count=summary.opt("steps");
        if(count==null||count==JSONObject.NULL){
            if(!PublicProfileBusinessAbsenceRecovery.CONTROL.equals(origin))throw new IOException("业务恢复归档缺少原始步骤数");
            return false;
        }
        long steps=number(summary,"steps");if(steps<0||steps>256)throw new IOException("业务恢复步骤数越界");return steps>0;
    }
    private static String originPath(JSONObject current)throws Exception{
        if(!"interrupted".equals(current.opt("status")))return PublicProfileBusinessAbsenceRecovery.CONTROL;
        JSONObject recovery=current.getJSONObject("startup_recovery");
        String sha=string(recovery,"previous_session_sha256");
        if(!sha.matches("[0-9a-f]{64}")||!"blocked".equals(string(recovery,"previous_status")))throw new IOException("业务恢复缺少真实原始终态归档链接");
        String relative="session-recovery/control-session.json."+sha+".json";
        JSONArray rows=recovery.getJSONArray("preserved_records");if(rows.length()!=1)throw new IOException("业务恢复原始会话归档集合不唯一");
        JSONObject row=rows.getJSONObject(0);
        if(!PublicProfileBusinessAbsenceRecovery.CONTROL.equals(string(row,"original_name"))||!sha.equals(string(row,"sha256"))
                ||!PublicProfileBusinessAbsenceRecovery.privatePathEnds(string(row,"path"),relative))throw new IOException("业务恢复归档链接不匹配");
        return relative;
    }

    static final class Receipt {
        final PublicProfileBusinessAbsenceRecovery.Request request;
        private final Context context;
        private final Inputs originals;
        private final String proofText,outputSha256,commandSha256;
        private final int outputBytes;
        private final long validatedElapsed;
        private MobiMindPrivateFiles.Read savedReceipt,savedManifest,savedOriginals;
        private String savedSha256;
        private Receipt(Context context,PublicProfileBusinessAbsenceRecovery.Request request,Inputs originals,JSONObject proof,
                byte[] output,String command,long now){
            this.context=context;this.request=request;this.originals=originals;proofText=proof.toString();outputSha256=sha(output);
            commandSha256=sha(command.getBytes(StandardCharsets.UTF_8));outputBytes=output.length;validatedElapsed=now;
        }
        JSONObject proof()throws Exception{return object(proofText.getBytes(StandardCharsets.UTF_8));}
        void requireOriginals(boolean journalPresent)throws Exception{originals.unchanged(journalPresent);}
        void requireCurrentClock()throws Exception{request.requireFence(SystemClock.elapsedRealtime(),boot(context));}
        void persist()throws Exception{
            if(savedReceipt!=null){requirePersisted();return;}
            requireCurrentClock();requireOriginals(true);originals.root.unchanged(context);
            File recovery=MobiMindPrivateFiles.directory(new File(originals.root.path,"session-recovery"),false);
            File dir=MobiMindPrivateFiles.directory(new File(recovery,"business-absence-"+request.requestId),true);
            byte[] manifest=PublicProfileBusinessAbsenceRecovery.canonical(request.manifest.json()).getBytes(StandardCharsets.UTF_8),archive=request.archiveBytes();
            File mf=new File(dir,"manifest.json"),bundle=new File(dir,"originals.bin");
            MobiMindPrivateFiles.writeNew(mf,manifest);MobiMindPrivateFiles.writeNew(bundle,archive);
            savedManifest=MobiMindPrivateFiles.read(mf,PublicProfileBusinessAbsenceRecovery.MAX_MANIFEST,true);
            savedOriginals=MobiMindPrivateFiles.read(bundle,archiveLimit(),true);
            if(!Arrays.equals(manifest,savedManifest.bytes)||!Arrays.equals(archive,savedOriginals.bytes))throw new IOException("业务恢复原件归档读回不一致");
            JSONObject value=new JSONObject().put("schema","hepta.public-profile-business-absence-commit.v1")
                    .put("source","owned_readonly_process_then_private_durable_business_receipt")
                    .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                    .put("journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256).put("manifest_sha256",request.manifest.sha256)
                    .put("original_manifest",fileRef(savedManifest)).put("complete_original_archive",fileRef(savedOriginals)).put("proof",proof())
                    .put("transport",new JSONObject().put("owned_process_exit_observed",true).put("exit_code",0).put("output_eof",true)
                            .put("output_complete",true).put("stdout_bytes",outputBytes).put("stdout_sha256",outputSha256).put("command_sha256",commandSha256))
                    .put("validated_elapsed_ms",validatedElapsed).put("business_steps",request.steps).put("model_requests",request.modelRequests)
                    .put("automatic_resume",false).put("rewrites_original_task_result",false).put("acknowledges_control_session",false).put("broker_release_response",false);
            byte[] bytes=value.toString(2).getBytes(StandardCharsets.UTF_8);File receipt=new File(dir,"receipt.json");
            MobiMindPrivateFiles.writeNew(receipt,bytes);MobiMindPrivateFiles.syncDirectory(dir);MobiMindPrivateFiles.syncDirectory(recovery);
            savedReceipt=MobiMindPrivateFiles.read(receipt,PublicProfileBusinessAbsenceRecovery.MAX_MANIFEST,true);savedSha256=sha(bytes);
            if(!Arrays.equals(bytes,savedReceipt.bytes))throw new IOException("业务恢复凭据读回不一致");
            requirePersisted();requireOriginals(true);requireCurrentClock();
        }
        void requirePersisted()throws Exception{
            if(savedReceipt==null||savedManifest==null||savedOriginals==null||savedSha256==null)throw new IOException("业务恢复凭据尚未完整持久保存");
            exact(savedReceipt,PublicProfileBusinessAbsenceRecovery.MAX_MANIFEST);exact(savedManifest,PublicProfileBusinessAbsenceRecovery.MAX_MANIFEST);exact(savedOriginals,archiveLimit());
            if(!savedSha256.equals(sha(savedReceipt.bytes))||!request.manifest.sha256.equals(sha(savedManifest.bytes)))throw new IOException("业务恢复凭据身份发生变化");
            originals.root.unchanged(context);
        }
        void requireLease(String task,String generation,String owner,long created,long expires,int boot,ProfileTarget target,PublicOwnGroupPolicy.Scope scope,int display)throws Exception{
            if(!request.taskId.equals(task)||!request.generation.equals(generation)||!request.ownerSha256.equals(owner)
                    ||request.created!=created||request.expires!=expires||request.oldBoot!=boot||target==null||!request.target.same(target)
                    ||scope==null||!request.publicScope.wire().equals(scope.wire())||!request.publicScope.sha256.equals(scope.sha256)||request.displayId!=display)
                throw new IOException("业务恢复凭据不属于原始公共租约");
            requirePersisted();requireOriginals(false);
        }
        String receiptSha256(){return savedSha256;}
        JSONObject evidence()throws Exception{
            requirePersisted();return new JSONObject().put("schema","hepta.background-reconcile.v1").put("generation",request.generation)
                    .put("cleanup_known",true).put("broker_released",false).put("broker_response",JSONObject.NULL)
                    .put("reconciliation_source",request.source()).put("public_profile_business_absence",proof())
                    .put("business_receipt_path",savedReceipt.path.getPath()).put("business_receipt_sha256",savedSha256)
                    .put("original_journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256).put("manifest_sha256",request.manifest.sha256)
                    .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true).put("display_absence_observed",true)
                    .put("business_steps",request.steps).put("model_requests",request.modelRequests).put("rewrites_original_task_result",false)
                    .put("acknowledges_control_session",false).put("automatic_resume",false);
        }
    }

    static Receipt collect(Context context,MobiMindPrivateFiles.Read journal,BackgroundSession.BusinessReconciliationCheck check)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("业务恢复的完整原件核验必须在后台执行");
        if(check==null)throw new IOException("业务恢复缺少实际任务和队列预约");
        check.check();LocalProbeApplication.requirePermissionPreparationIdle(context);
        Inputs inputs=new Inputs(context,journal);check.checkBusiness(inputs.taskId,inputs.ownerSha);inputs.readAll();
        requireModelGeneration(inputs);
        int uid=android.os.Process.myUid();JSONObject controller=RecoveryControllerIdentity.read(context,uid,SystemClock.elapsedRealtime()+PublicProfileBusinessAbsenceRecovery.LIMIT_MS);
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.getPath().equals(string(controller,"source_path")))throw new IOException("业务恢复当前代码与实际安装身份不一致");
        inputs.unchanged(true);check.checkBusiness(inputs.taskId,inputs.ownerSha);
        long started=SystemClock.elapsedRealtime();JSONObject value=new JSONObject().put("schema",PublicProfileBusinessAbsenceRecovery.REQUEST_SCHEMA)
                .put("owner_uid",uid).put("request_id",UUID.randomUUID().toString()).put("task_id",inputs.taskId).put("started_elapsed_ms",started)
                .put("boot_count",boot(context)).put("current_controller",controller).put("origin_summary",inputs.origin)
                .put("files",inputs.descriptors()).put("task_membership",new JSONArray(inputs.taskFiles));
        PublicProfileBusinessAbsenceRecovery.Request request=PublicProfileBusinessAbsenceRecovery.request(PublicProfileBusinessAbsenceRecovery.manifest(value),inputs.bytes());
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / org.trillionnium.hepta.background.PublicProfileBusinessRecoveryMain --request "+quote(request.wire());
        if(command.getBytes(StandardCharsets.UTF_8).length>=60000)throw new IOException("业务恢复命令超过原完整进程读取上限");
        check.checkBusiness(request.taskId,request.ownerSha256);request.requireFence(SystemClock.elapsedRealtime(),boot(context));
        final Flight flight=new Flight();if(!ACTIVE.compareAndSet(null,flight))throw new IOException("已有业务恢复检查器尚未真实退出");
        try{
            Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();flight.process=process;
            Capture capture=new Capture(process.getInputStream());flight.capture=capture;
            Thread reader=new Thread(capture,"hepta-business-absence-output");reader.setDaemon(true);flight.reader=reader;reader.start();
            process.getOutputStream().close();long remaining=request.deadline-SystemClock.elapsedRealtime();
            if(remaining<=0||!process.waitFor(remaining,TimeUnit.MILLISECONDS))throw new IOException("业务恢复只读检查超过原始期限");
            remaining=request.deadline-SystemClock.elapsedRealtime();if(remaining>0)reader.join(remaining);
            if(reader.isAlive()||!capture.finished||capture.failure!=null||!capture.eof)throw new IOException("后台状态检查未返回完整结果");
            int exit=process.exitValue();
            if(exit!=0){
                if(exit==70&&"RECOVERY_PROC_CENSUS_UNSTABLE".equals(checkerFailureCode(request,capture.bytes)))
                    throw new IOException("检查期间有系统进程退出，暂时无法确认后台空间已释放。稍后可再次点击“清理上一次后台空间”。");
                throw new IOException("后台状态检查未能确认空间已释放（退出码 "+exit+"）");
            }
            JSONObject verified=PublicProfileBusinessAbsenceRecovery.validate(object(capture.bytes),request,SystemClock.elapsedRealtime(),boot(context));
            if(!PublicProfileBusinessAbsenceRecovery.same(controller,RecoveryControllerIdentity.read(context,uid,request.deadline)))throw new IOException("业务恢复期间安装代码发生变化");
            check.checkBusiness(request.taskId,request.ownerSha256);inputs.unchanged(true);request.requireFence(SystemClock.elapsedRealtime(),boot(context));
            return new Receipt(context,request,inputs,verified,capture.bytes,command,SystemClock.elapsedRealtime());
        }catch(Exception failure){
            try{recordFailure(inputs,request,flight,command,failure);}catch(Exception archive){failure.addSuppressed(archive);}throw failure;
        }finally{flight.finishOrDrain();}
    }

    private static final class Inputs {
        final Context context;final QualificationScopeConfig.FilesRoot root;final File task;
        final String taskId,ownerSha,origin,taskKey;
        final TreeSet<String> taskFiles;
        private File otherModelTerminal;
        final TreeMap<String,MobiMindPrivateFiles.Read> reads=new TreeMap<String,MobiMindPrivateFiles.Read>();
        Inputs(Context context,MobiMindPrivateFiles.Read journal)throws Exception{
            this.context=context;root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
            JSONObject j=object(journal.bytes);taskId=string(j,"task_id");ownerSha=string(j,"owner_sha256");
            if(!taskId.matches("[0-9a-f]{32}")||!ownerSha.matches("[0-9a-f]{64}")||!journal.path.equals(new File(root.path,PublicProfileBusinessAbsenceRecovery.JOURNAL)))throw new IOException("业务恢复私有任务身份无效");
            reads.put(PublicProfileBusinessAbsenceRecovery.JOURNAL,journal);
            task=new File(existingDirectory(new File(root.path,"control-tasks")),taskId);taskKey=directoryIdentity(task);
            taskFiles=members(task);read(PublicProfileBusinessAbsenceRecovery.CONTROL,SUMMARY_LIMIT);
            origin=originPath(object(reads.get(PublicProfileBusinessAbsenceRecovery.CONTROL).bytes));if(!origin.equals(PublicProfileBusinessAbsenceRecovery.CONTROL))read(origin,SUMMARY_LIMIT);
            if(MobiMindPrivateFiles.exists(new File(root.path,PublicProfileBusinessAbsenceRecovery.LATCH)))read(PublicProfileBusinessAbsenceRecovery.LATCH,SUMMARY_LIMIT);
            stableMetadata();
        }
        void readAll()throws Exception{
            for(String name:taskFiles){
                String path="control-tasks/"+taskId+"/"+name;read(path,PublicProfileBusinessAbsenceRecovery.originalLimit(path));
            }
            JSONObject result=object(get("control-tasks/"+taskId+"/result.json"));String generation=string(result.getJSONObject("model_session"),"worker_generation");
            if(!generation.matches("[0-9a-f]{32}"))throw new IOException("业务恢复原模型 generation 无效");String prefix="runs/"+generation+"/";
            boolean text=MobiMindPrivateFiles.exists(new File(root.path,prefix+"app-session-receipt.json"));
            boolean visual=MobiMindPrivateFiles.exists(new File(root.path,prefix+"vlm-task-terminal.json"));
            if(text==visual)throw new IOException("业务恢复需要此任务唯一的本地模型退出记录");
            otherModelTerminal=new File(root.path,prefix+(visual?"app-session-receipt.json":"vlm-task-terminal.json"));
            if(visual){
                String terminal=prefix+"vlm-task-terminal.json";read(terminal,PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);
                for(String path:PublicProfileBusinessAbsenceRecovery.visualModelPaths(object(get(terminal)),taskId,generation))
                    read(path,PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);
                unchanged(true);return;
            }
            read(prefix+"app-session-receipt.json",PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);read(prefix+"native-session-result.json",PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);
            JSONObject session=object(get(prefix+"app-session-receipt.json"));String nonce=string(session.getJSONObject("worker_generation_cleanup"),"cleanup_nonce");
            if(!nonce.matches("[0-9a-f]{32}"))throw new IOException("业务恢复原模型退出 nonce 无效");
            read(prefix+"worker-generation.identity",PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);read(prefix+"generation-cleanup-"+nonce+".json",PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);
            for(String name:taskFiles)if(name.matches("step-[0-9]+-model-[0-9]+\\.json")){
                String run=string(object(get("control-tasks/"+taskId+"/"+name)),"run_id");if(!run.matches("[0-9a-f]{32}"))throw new IOException("业务恢复原模型 request 无效");
                for(String leaf:new String[]{"app-receipt.json","native-result.json","raw-text.txt"})read("runs/"+run+"/"+leaf,PublicProfileBusinessAbsenceRecovery.MAX_ORIGINAL);
            }
            unchanged(true);
        }
        void read(String relative,int limit)throws Exception{
            PublicProfileBusinessAbsenceRecovery.requireRelative(relative,taskId);if(reads.containsKey(relative))return;
            File path=new File(root.path,relative);File parent=path.getParentFile();while(!parent.equals(root.path)){existingDirectory(parent);parent=parent.getParentFile();if(parent==null)throw new IOException("业务恢复路径不属于当前私有根");}
            MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,limit,true);descriptor(read,relative);
            reads.put(relative,read);long total=0;for(MobiMindPrivateFiles.Read value:reads.values())total+=value.bytes.length;
            if(reads.size()>PublicProfileBusinessAbsenceRecovery.MAX_FILES||total>PublicProfileBusinessAbsenceRecovery.MAX_BUNDLE)throw new IOException("业务恢复完整原件总量超过上限");
        }
        byte[] get(String relative)throws Exception{MobiMindPrivateFiles.Read read=reads.get(relative);if(read==null)throw new IOException("业务恢复完整原件缺失");return read.bytes;}
        Map<String,byte[]> bytes(){Map<String,byte[]> result=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,MobiMindPrivateFiles.Read> e:reads.entrySet())result.put(e.getKey(),e.getValue().bytes);return result;}
        JSONObject descriptors()throws Exception{JSONObject value=new JSONObject();for(Map.Entry<String,MobiMindPrivateFiles.Read> e:reads.entrySet())value.put(e.getKey(),descriptor(e.getValue(),e.getKey()));return value;}
        void unchanged(boolean leasePresent)throws Exception{
            stableMetadata();for(Map.Entry<String,MobiMindPrivateFiles.Read> e:reads.entrySet()){
                if(!leasePresent&&PublicProfileBusinessAbsenceRecovery.JOURNAL.equals(e.getKey()))continue;
                exact(e.getValue(),PublicProfileBusinessAbsenceRecovery.originalLimit(e.getKey()));
            }stableMetadata();
            if(!leasePresent&&MobiMindPrivateFiles.exists(new File(root.path,PublicProfileBusinessAbsenceRecovery.JOURNAL)))throw new IOException("业务恢复已提交后租约再次出现");
        }
        private void stableMetadata()throws Exception{
            root.unchanged(context);if(!taskKey.equals(directoryIdentity(task))||!taskFiles.equals(members(task)))throw new IOException("业务恢复原任务目录集合发生变化");
            if(otherModelTerminal!=null&&MobiMindPrivateFiles.exists(otherModelTerminal))throw new IOException("业务恢复期间新增了另一种本地模型退出记录");
            for(String name:new String[]{"control-session.json.bak","control-session.json.new"})if(MobiMindPrivateFiles.exists(new File(root.path,name)))throw new IOException("业务恢复遇到未提交会话记录");
            if(!reads.containsKey(PublicProfileBusinessAbsenceRecovery.LATCH)&&MobiMindPrivateFiles.exists(new File(root.path,PublicProfileBusinessAbsenceRecovery.LATCH)))throw new IOException("业务恢复期间新增中断标记");
            if(!new RecoveryJournalStore(context).pendingBarriers().isEmpty())throw new IOException("业务恢复遇到待提交控制确认");
        }
    }
    private static void requireModelGeneration(Inputs inputs)throws Exception{
        JSONObject result=object(inputs.get("control-tasks/"+inputs.taskId+"/result.json"));String generation=string(result.getJSONObject("model_session"),"worker_generation"),prefix="runs/"+generation+"/";
        if(inputs.reads.containsKey(prefix+"vlm-task-terminal.json")){
            JSONArray rounds=object(inputs.get(prefix+"vlm-task-terminal.json")).getJSONArray("requests");
            for(int i=0;i<rounds.length();i++){
                JSONObject round=rounds.getJSONObject(i);String worker=string(round,"generation"),workerPrefix="runs/"+worker+"/";
                JSONObject app=object(inputs.get(workerPrefix+"vlm/"+string(round,"request_id")+"/app-receipt.json"));
                bindGeneration(inputs,worker,workerPrefix,app,round.getJSONObject("generation_cleanup"));
            }
            return;
        }
        JSONObject session=object(inputs.get(prefix+"app-session-receipt.json"));
        bindGeneration(inputs,generation,prefix,session,session.getJSONObject("worker_generation_cleanup"));
    }
    private static void bindGeneration(Inputs inputs,String generation,String prefix,JSONObject session,JSONObject g)throws Exception{
        String nonce=string(g,"cleanup_nonce");
        WorkerGenerationProof.Expected expected=new WorkerGenerationProof.Expected(inputs.taskId,generation,string(g,"scope_token"),string(g,"boot_id"),number(g,"app_uid"),number(g,"app_pid"),number(g,"app_start_ticks"));
        WorkerGenerationProof.Identity identity=WorkerGenerationProof.identity(inputs.get(prefix+"worker-generation.identity"),expected);
        JSONObject nativeReceipt=object(inputs.get(prefix+"generation-cleanup-"+nonce+".json"));
        WorkerGenerationProof.bindCleanup(identity,nonce,number(g,"submitted_monotonic_ns"),number(g,"deadline_monotonic_ns"),
                number(session,"finisher_submitted_monotonic_ns"),number(session,"finisher_deadline_monotonic_ns"),nativeReceipt,
                Boolean.TRUE.equals(g.get("helper_exit_observed")),Integer.valueOf((int)number(g,"helper_exit_code")),!Boolean.FALSE.equals(g.get("helper_force_destroy_sent")));
        if(WorkerGenerationProof.boundForceAttempts(identity,nonce,nativeReceipt)!=0||number(nativeReceipt,"term_attempts")!=0||number(nativeReceipt,"kill_attempts")!=0
                ||nativeReceipt.getJSONArray("targets").length()!=0)throw new IOException("业务恢复要求已记录的非强制完整模型退出");
    }
    private static final class Flight {
        volatile Process process;volatile Thread reader;volatile Capture capture;
        private boolean drained;private Runnable completion;
        synchronized void whenDrained(Runnable value){if(drained){value.run();return;}if(completion!=null)throw new IllegalStateException("owned checker already has its completion");completion=value;}
        void finishOrDrain(){
            Process p=process;Capture c=capture;Thread r=reader;
            if(p==null||!p.isAlive()&&c!=null&&c.finished&&r!=null&&!r.isAlive()){finish();return;}
            // Only the process created here may receive this cancellation. Its root
            // checker also has its own unchanged absolute deadline and watchdog.
            try{p.destroy();}catch(Throwable ignored){}
            Thread drain=new Thread(()->{
                try{p.waitFor();if(r!=null)r.join();if(c!=null&&c.finished)finish();}
                catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            },"hepta-business-absence-drain");drain.setDaemon(true);drain.start();
        }
        private void finish(){Runnable done;synchronized(this){if(drained)return;drained=true;ACTIVE.compareAndSet(this,null);done=completion;completion=null;}if(done!=null)done.run();}
    }
    private static final class Capture implements Runnable {
        final InputStream input;volatile byte[] bytes;volatile Throwable failure;volatile boolean eof,finished;
        Capture(InputStream input){this.input=input;}
        public void run(){ByteArrayOutputStream output=new ByteArrayOutputStream();try(InputStream owned=input){byte[] block=new byte[4096];int n;
            while((n=owned.read(block))!=-1){if(output.size()+n>PublicProfileBusinessAbsenceRecovery.MAX_OUTPUT)throw new IOException("业务恢复输出超过完整读取上限");output.write(block,0,n);}eof=true;
        }catch(Throwable error){failure=error;}finally{bytes=output.toByteArray();finished=true;}}
    }
    private static String checkerFailureCode(PublicProfileBusinessAbsenceRecovery.Request request,byte[] output){
        try{
            JSONObject failure=object(output);
            if(!request.proofSchema().equals(failure.opt("schema"))||!request.requestId.equals(failure.opt("request_id"))
                    ||!Boolean.FALSE.equals(failure.opt("cleanup_known")))return "";
            String code=string(failure,"error");return code.matches("[A-Z0-9_]{1,96}")?code:"";
        }catch(Exception unparsed){return "";}
    }
    private static void recordFailure(Inputs inputs,PublicProfileBusinessAbsenceRecovery.Request request,Flight flight,String command,Exception error)throws Exception{
        inputs.root.unchanged(inputs.context);File recovery=MobiMindPrivateFiles.directory(new File(inputs.root.path,"session-recovery"),false);
        File dir=MobiMindPrivateFiles.directory(new File(recovery,"business-absence-failed-"+request.requestId),true);
        Process process=flight.process;Capture capture=flight.capture;boolean exited=process!=null&&!process.isAlive();
        JSONObject value=new JSONObject().put("schema","hepta.public-profile-business-absence-failed-attempt.v1").put("request_id",request.requestId)
                .put("task_id",request.taskId).put("generation",request.generation).put("manifest_sha256",request.manifest.sha256).put("originals_sha256",request.originalsSha256)
                .put("owned_process_exit_observed",exited).put("exit_code",exited?process.exitValue():JSONObject.NULL)
                .put("reader_finished",capture!=null&&capture.finished).put("output_eof",capture!=null&&capture.eof)
                .put("command_sha256",sha(command.getBytes(StandardCharsets.UTF_8))).put("error_class",error.getClass().getName())
                .put("cleanup_known",false).put("lease_retired",false).put("automatic_resume",false).put("rewrites_original_task_result",false);
        if(capture!=null&&capture.finished&&capture.bytes!=null){byte[] output=capture.bytes;File raw=new File(dir,"checker-output.bin");MobiMindPrivateFiles.writeNew(raw,output);
            value.put("output_bytes",output.length).put("output_sha256",sha(output));
            String code=checkerFailureCode(request,output);if(!code.isEmpty())value.put("checker_error",code);}
        MobiMindPrivateFiles.writeNew(new File(dir,"attempt.json"),value.toString(2).getBytes(StandardCharsets.UTF_8));
    }
    private static JSONObject fileRef(MobiMindPrivateFiles.Read value)throws Exception{return new JSONObject().put("file",value.path.getName()).put("bytes",value.bytes.length).put("sha256",sha(value.bytes));}
    private static JSONObject descriptor(MobiMindPrivateFiles.Read read,String relative)throws Exception{return descriptor(read.stat,read.bytes,relative);}
    private static JSONObject descriptor(StructStat st,byte[] bytes,String relative)throws Exception{
        if(st.st_size!=bytes.length)throw new IOException("业务恢复私有原件长度改变");
        JSONObject d=new JSONObject().put("bytes",bytes.length).put("sha256",sha(bytes)).put("device",st.st_dev).put("inode",st.st_ino).put("uid",st.st_uid).put("mode",st.st_mode).put("nlink",st.st_nlink)
                .put("mtime_seconds",time(st,"st_mtim","tv_sec")).put("mtime_nanos",time(st,"st_mtim","tv_nsec")).put("ctime_seconds",time(st,"st_ctim","tv_sec")).put("ctime_nanos",time(st,"st_ctim","tv_nsec"));
        PublicProfileBusinessAbsenceRecovery.requireDescriptor(d,android.os.Process.myUid(),PublicProfileBusinessAbsenceRecovery.originalLimit(relative));return d;
    }
    private static long time(StructStat st,String field,String part)throws Exception{Object value=StructStat.class.getField(field).get(st),n=value.getClass().getField(part).get(value);if(!(n instanceof Long))throw new IOException("业务恢复私有原件时间不完整");return (Long)n;}
    private static void exact(MobiMindPrivateFiles.Read first,int limit)throws Exception{
        first.unchangedPath();MobiMindPrivateFiles.Read now=MobiMindPrivateFiles.read(first.path,limit,true);
        // Archive bundles exceed the per-original limit; their full bytes and exact
        // stat clocks are still bound, without pretending they were original files.
        if(!Arrays.equals(first.bytes,now.bytes)||!sameStat(first.stat,now.stat)||!sameStat(first.stat,Os.lstat(first.path.getPath())))throw new IOException("业务恢复期间私有原件或归档发生变化");
    }
    private static boolean sameStat(StructStat a,StructStat b)throws Exception{return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_uid==b.st_uid&&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink
            &&time(a,"st_mtim","tv_sec")==time(b,"st_mtim","tv_sec")&&time(a,"st_mtim","tv_nsec")==time(b,"st_mtim","tv_nsec")
            &&time(a,"st_ctim","tv_sec")==time(b,"st_ctim","tv_sec")&&time(a,"st_ctim","tv_nsec")==time(b,"st_ctim","tv_nsec");}
    private static TreeSet<String> members(File dir)throws Exception{String[] rows=dir.list();if(rows==null||rows.length>PublicProfileBusinessAbsenceRecovery.MAX_FILES)throw new IOException("业务恢复任务目录不可完整枚举");TreeSet<String> out=new TreeSet<String>();for(String row:rows)if(!PublicProfileBusinessAbsenceRecovery.leaf(row)||!out.add(row))throw new IOException("业务恢复任务目录名称无效");return out;}
    private static File existingDirectory(File path)throws Exception{directoryIdentity(path);return path;}
    private static String directoryIdentity(File path)throws Exception{if(!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new IOException("业务恢复私有目录别名被拒绝");StructStat s=Os.lstat(path.getPath());if(!OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=android.os.Process.myUid()||(s.st_mode&0777)!=0700)throw new IOException("业务恢复私有目录归属不明");return s.st_dev+":"+s.st_ino+":"+s.st_uid+":"+s.st_mode;}
    private static int archiveLimit(){return PublicProfileBusinessAbsenceRecovery.MAX_BUNDLE+PublicProfileBusinessAbsenceRecovery.MAX_MANIFEST+PublicProfileBusinessAbsenceRecovery.MAX_FILES*512+4096;}
    private static int boot(Context context){return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);}
    private static JSONObject object(byte[] bytes)throws Exception{return PublicProfileBusinessAbsenceRecovery.object(bytes);}
    private static String string(JSONObject value,String key)throws Exception{return PublicProfileBusinessAbsenceRecovery.string(value,key);}
    private static long number(JSONObject value,String key)throws Exception{return PublicProfileBusinessAbsenceRecovery.number(value,key);}
    private static String sha(byte[] bytes){return HeptaAccessibilityService.sha(bytes);}
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
