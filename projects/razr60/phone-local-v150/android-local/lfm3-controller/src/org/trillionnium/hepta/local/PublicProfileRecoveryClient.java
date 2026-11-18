package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.SystemClock;
import android.provider.Settings;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileAbsenceRecovery;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Only the ordinary cleanup worker obtains this opaque public-scope receipt.
 * Historical task files remain byte-exact; no process-discovery PID is signalled. */
final class PublicProfileRecoveryClient {
    private PublicProfileRecoveryClient(){}
    static final class Receipt {
        final PublicProfileAbsenceRecovery.Request request;
        private final String proofText,outputSha256,commandSha256;
        private final int outputBytes;
        private final long validatedElapsed;
        private final Map<String,MobiMindPrivateFiles.Read> originals;
        private File savedReceipt;
        private String savedSha256;
        private final Map<String,File> archives=new LinkedHashMap<String,File>();
        private Receipt(PublicProfileAbsenceRecovery.Request request,JSONObject proof,byte[] output,String command,long now,
                Map<String,MobiMindPrivateFiles.Read> originals){
            this.request=request;proofText=proof.toString();outputSha256=HeptaAccessibilityService.sha(output);
            commandSha256=HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8));outputBytes=output.length;
            validatedElapsed=now;this.originals=new LinkedHashMap<String,MobiMindPrivateFiles.Read>(originals);
        }
        JSONObject proof()throws Exception{return PublicProfileAbsenceRecovery.object(proofText.getBytes(StandardCharsets.UTF_8));}
        void requireOriginals(boolean journalPresent)throws Exception{
            for(Map.Entry<String,MobiMindPrivateFiles.Read> item:originals.entrySet()){
                if(!journalPresent&&"journal".equals(item.getKey()))continue;
                MobiMindPrivateFiles.Read first=item.getValue();first.unchangedPath();
                byte[] actual=MobiMindPrivateFiles.read(first.path,PublicProfileAbsenceRecovery.MAX_ORIGINAL,true).bytes;
                if(!Arrays.equals(actual,request.original(item.getKey())))throw new IOException("公共恢复期间原始失败记录发生变化");
            }
        }
        void persist(Context context)throws Exception{
            if(savedReceipt!=null){requirePersisted();return;}
            requireOriginals(true);QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
            File task=existingDirectory(new File(existingDirectory(new File(root.path,"control-tasks")),request.taskId));
            String base="background-public-absence-"+request.requestId;JSONObject refs=new JSONObject();
            for(String name:originals.keySet()){
                File archive=new File(task,base+".original-"+name+".bin");byte[] raw=request.original(name);
                createOrRequireExact(archive,raw);archives.put(name,archive);
                refs.put(name,new JSONObject().put("file",archive.getName()).put("bytes",raw.length).put("sha256",HeptaAccessibilityService.sha(raw)));
            }
            JSONObject value=new JSONObject().put("schema","hepta.public-profile-absence-commit.v1")
                    .put("source","owned_readonly_process_then_private_durable_receipt")
                    .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                    .put("journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256)
                    .put("original_archives",refs).put("proof",proof())
                    .put("transport",new JSONObject().put("owned_process_exit_observed",true).put("exit_code",0).put("output_eof",true)
                            .put("output_complete",true).put("stdout_bytes",outputBytes).put("stdout_sha256",outputSha256).put("command_sha256",commandSha256))
                    .put("validated_elapsed_ms",validatedElapsed).put("automatic_resume",false).put("rewrites_original_task_result",false)
                    .put("historical_creation_unknown",true).put("broker_release_response",false);
            byte[] raw=value.toString(2).getBytes(StandardCharsets.UTF_8);File receipt=new File(task,base+".json");
            createOrRequireExact(receipt,raw);MobiMindPrivateFiles.syncDirectory(task);
            savedReceipt=receipt;savedSha256=HeptaAccessibilityService.sha(raw);
            requirePersisted();requireOriginals(true);root.unchanged(context);
        }
        private static void createOrRequireExact(File file,byte[] raw)throws Exception{
            if(MobiMindPrivateFiles.exists(file)){
                if(!Arrays.equals(raw,MobiMindPrivateFiles.read(file,PublicProfileAbsenceRecovery.MAX_BUNDLE,true).bytes))
                    throw new IOException("恢复请求的已有归档不是同一字节记录");
            }else MobiMindPrivateFiles.writeNew(file,raw);
        }
        void requirePersisted()throws Exception{
            if(savedReceipt==null||savedSha256==null||archives.size()!=originals.size())throw new IOException("公共恢复凭据尚未持久保存");
            byte[] raw=MobiMindPrivateFiles.read(savedReceipt,PublicProfileAbsenceRecovery.MAX_BUNDLE,true).bytes;
            if(!savedSha256.equals(HeptaAccessibilityService.sha(raw)))throw new IOException("公共恢复收据发生变化");
            for(Map.Entry<String,File> item:archives.entrySet())if(!Arrays.equals(request.original(item.getKey()),
                    MobiMindPrivateFiles.read(item.getValue(),PublicProfileAbsenceRecovery.MAX_ORIGINAL,true).bytes))
                throw new IOException("公共恢复的原始字节归档发生变化");
        }
        void requireLease(String task,String generation,String owner,long created,long expires,int boot,ProfileTarget target,PublicOwnGroupPolicy.Scope scope)throws Exception{
            if(!request.taskId.equals(task)||!request.generation.equals(generation)||!request.ownerSha256.equals(owner)
                    ||request.created!=created||request.expires!=expires||request.oldBoot!=boot||target==null||!request.target.same(target)
                    ||scope==null||!request.publicScope.wire().equals(scope.wire())||!request.publicScope.sha256.equals(scope.sha256))
                throw new IOException("公共恢复凭据不属于当前原始租约");
            requirePersisted();requireOriginals(false);
        }
        String receiptSha256(){return savedSha256;}
        JSONObject evidence()throws Exception{
            requirePersisted();return new JSONObject().put("schema","hepta.background-reconcile.v1").put("generation",request.generation)
                    .put("cleanup_known",true).put("broker_released",false).put("broker_response",JSONObject.NULL)
                    .put("reconciliation_source",PublicProfileAbsenceRecovery.SOURCE).put("public_profile_absence",proof())
                    .put("public_profile_receipt_path",savedReceipt.getPath()).put("public_profile_receipt_sha256",savedSha256)
                    .put("original_journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256)
                    .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true)
                    .put("historical_creation_unknown",true).put("display_absence_observed",true).put("automatic_resume",false);
        }
    }
    static Receipt collect(Context context,MobiMindPrivateFiles.Read journal,BackgroundSession.ReconciliationCheck check)throws Exception{
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())throw new IllegalStateException("公共租约恢复须在后台核验");
        if(check==null)throw new IOException("公共恢复缺少普通 UI 会话门槛");check.check();LocalProbeApplication.requirePermissionPreparationIdle(context);
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);journal.unchangedPath();
        JSONObject old=PublicProfileAbsenceRecovery.object(journal.bytes);String taskId=PublicProfileAbsenceRecovery.string(old,"task_id");
        String generation=PublicProfileAbsenceRecovery.string(old,"generation");
        if(!taskId.matches("[0-9a-f]{32}")||!generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw new IOException("公共恢复的原任务身份无效");
        File task=existingDirectory(new File(existingDirectory(new File(root.path,"control-tasks")),taskId));
        String[] leaves=task.list();if(leaves==null)throw new IOException("公共恢复的原任务目录不可读");
        for(String name:leaves)if(name.matches("step-[0-9]+-.*")||name.startsWith("ime-submit-")||name.startsWith("fixed-intent-")
                ||name.startsWith("native-app-")||name.startsWith("controller-completion-"))throw new IOException("公共恢复发现原任务已有模型或业务步骤");
        Map<String,MobiMindPrivateFiles.Read> actual=new LinkedHashMap<String,MobiMindPrivateFiles.Read>();actual.put("journal",journal);
        for(String[] item:new String[][]{{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},
                {"result","result.json"},{"broker_receipt","background-broker-"+generation+".json"},{"broker_output","background-broker-"+generation+".bin"}})
            actual.put(item[0],MobiMindPrivateFiles.read(new File(task,item[1]),PublicProfileAbsenceRecovery.MAX_ORIGINAL,true));
        Map<String,byte[]> originals=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,MobiMindPrivateFiles.Read> entry:actual.entrySet())originals.put(entry.getKey(),entry.getValue().bytes);
        int uid=android.os.Process.myUid(),boot=Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);
        JSONObject controller=RecoveryControllerIdentity.read(context,uid,SystemClock.elapsedRealtime()+PublicProfileAbsenceRecovery.LIMIT_MS);
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.getPath().equals(PublicProfileAbsenceRecovery.string(controller,"source_path")))throw new IOException("公共恢复的当前代码与安装身份不一致");
        PublicProfileAbsenceRecovery.Request request=PublicProfileAbsenceRecovery.request(originals,controller,uid,UUID.randomUUID().toString(),SystemClock.elapsedRealtime(),boot);
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / org.trillionnium.hepta.background.PublicProfileRecoveryMain --request "+quote(request.wire());
        // The complete command must also fit the unchanged root proc-census bound.
        if(command.getBytes(StandardCharsets.UTF_8).length>=60000)throw new IOException("公共恢复命令超过完整进程核验上限");
        check.check();for(MobiMindPrivateFiles.Read first:actual.values())first.unchangedPath();
        final Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        final Capture capture=new Capture(process.getInputStream());Thread reader=new Thread(capture,"hepta-public-profile-recovery-read");reader.setDaemon(true);reader.start();
        boolean exited=false;
        try{
            process.getOutputStream().close();long left=request.deadline-SystemClock.elapsedRealtime();
            if(left<=0||!process.waitFor(left,TimeUnit.MILLISECONDS))throw new IOException("公共租约只读核验超时");exited=true;
            left=request.deadline-SystemClock.elapsedRealtime();if(left>0)reader.join(left);
            if(reader.isAlive()||capture.failure!=null||!capture.eof||process.exitValue()!=0)throw new IOException("公共租约核验没有完整成功回执");
            byte[] output=capture.bytes;JSONObject verified=PublicProfileAbsenceRecovery.validate(PublicProfileAbsenceRecovery.object(output),request,
                    SystemClock.elapsedRealtime(),Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1));
            if(!PublicProfileAbsenceRecovery.same(controller,RecoveryControllerIdentity.read(context,uid,request.deadline)))throw new IOException("公共恢复期间当前安装代码发生变化");
            check.check();Receipt receipt=new Receipt(request,verified,output,command,SystemClock.elapsedRealtime(),actual);
            receipt.requireOriginals(true);request.requireFence(SystemClock.elapsedRealtime(),Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1));
            return receipt;
        }catch(Exception error){
            // A failed check never becomes cleanup authority. Retain this new attempt for diagnosis.
            try{recordFailedAttempt(context,request,capture,reader,process,exited,command,error);}
            catch(Exception archiveFailure){error.addSuppressed(archiveFailure);}
            throw error;
        }finally{if(!exited)process.destroy();}
    }
    private static void recordFailedAttempt(Context context,PublicProfileAbsenceRecovery.Request request,Capture capture,
            Thread reader,Process process,boolean exited,String command,Exception error)throws Exception{
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
        File task=existingDirectory(new File(existingDirectory(new File(root.path,"control-tasks")),request.taskId));
        String base="background-public-absence-"+request.requestId;byte[] output=reader.isAlive()?null:capture.bytes;
        JSONObject value=new JSONObject().put("schema","hepta.public-profile-absence-failed-attempt.v1")
                .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                .put("journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256)
                .put("original_inputs",request.inputHashes()).put("current_controller",request.controller())
                .put("command_sha256",HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8)))
                .put("owned_process_exit_observed",exited).put("exit_code",exited?process.exitValue():JSONObject.NULL)
                .put("reader_alive",reader.isAlive()).put("output_eof",capture.eof)
                .put("output_complete",!reader.isAlive()&&capture.eof&&capture.failure==null)
                .put("read_failure_class",capture.failure==null?JSONObject.NULL:capture.failure.getClass().getName())
                .put("error_class",error.getClass().getName()).put("cleanup_known",false).put("lease_retired",false)
                .put("automatic_resume",false).put("rewrites_original_task_result",false);
        if(output!=null){File raw=new File(task,base+".checker-output.bin");MobiMindPrivateFiles.writeNew(raw,output);
            value.put("output_file",raw.getName()).put("output_bytes",output.length).put("output_sha256",HeptaAccessibilityService.sha(output));
            if(capture.eof&&capture.failure==null){try{JSONObject diagnostic=PublicProfileAbsenceRecovery.object(output);
                String code=PublicProfileAbsenceRecovery.string(diagnostic,"error");
                if(PublicProfileAbsenceRecovery.SCHEMA.equals(diagnostic.optString("schema"))&&request.requestId.equals(diagnostic.optString("request_id"))
                        &&Boolean.FALSE.equals(diagnostic.get("cleanup_known"))&&code.matches("[A-Z0-9_]{1,96}"))value.put("checker_error",code);
            }catch(Exception notAnErrorRecord){/* Retain actual bytes without treating them as a proof. */}}
        }
        MobiMindPrivateFiles.writeNew(new File(task,base+".attempt.json"),value.toString(2).getBytes(StandardCharsets.UTF_8));
        MobiMindPrivateFiles.syncDirectory(task);root.unchanged(context);
    }
    private static File existingDirectory(File path)throws Exception{
        if(!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new IOException("公共恢复归档路径不是原始私有目录");
        android.system.StructStat s=android.system.Os.lstat(path.getPath());
        if(!android.system.OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=android.os.Process.myUid()||(s.st_mode&0777)!=0700)
            throw new IOException("公共恢复的既有任务目录缺失或归属不明");return path;
    }
    private static final class Capture implements Runnable{
        private final InputStream input;volatile byte[] bytes;volatile Throwable failure;volatile boolean eof;
        Capture(InputStream input){this.input=input;}
        public void run(){ByteArrayOutputStream output=new ByteArrayOutputStream();try(InputStream owned=input){
            byte[] block=new byte[4096];int count;while((count=owned.read(block))!=-1){if(output.size()+count>PublicProfileAbsenceRecovery.MAX_OUTPUT)
                throw new IOException("公共恢复输出超过上限");output.write(block,0,count);}eof=true;
        }catch(Throwable failed){failure=failed;}finally{bytes=output.toByteArray();}}
    }
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
