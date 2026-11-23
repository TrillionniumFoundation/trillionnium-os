package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.SystemClock;
import android.provider.Settings;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfilePostlaunchRecovery;
import org.trillionnium.hepta.background.ProfileTarget;

/** Only the ordinary cleanup worker can obtain this owned-process, durably retained proof. */
final class ProfilePostlaunchRecoveryClient {
    private ProfilePostlaunchRecoveryClient(){}
    static final class Receipt {
        final ProfilePostlaunchRecovery.Request request;
        private final String proofText,outputSha256,commandSha256;
        private final int outputBytes;
        private final long validatedElapsed;
        private File savedReceipt,savedJournal;
        private String savedSha256;
        private Receipt(ProfilePostlaunchRecovery.Request request,JSONObject proof,byte[] output,String command,long validatedElapsed){
            this.request=request;proofText=proof.toString();outputSha256=HeptaAccessibilityService.sha(output);
            outputBytes=output.length;commandSha256=HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8));
            this.validatedElapsed=validatedElapsed;
        }
        JSONObject proof()throws Exception{return new JSONObject(proofText);}
        void requireLease(String task,String generation,String ownerSha,long created,long expires,int boot,ProfileTarget target,int display)throws Exception{
            if(!request.taskId.equals(task)||!request.generation.equals(generation)||!request.ownerSha256.equals(ownerSha)
                    ||request.created!=created||request.expires!=expires||request.oldBoot!=boot
                    ||target==null||!request.target.same(target)||request.displayId!=display)throw new java.io.IOException("恢复凭据不属于原始已启动租约");
            requirePersisted();
        }
        void persist(Context context)throws Exception{
            if(savedReceipt!=null||savedJournal!=null)throw new java.io.IOException("恢复凭据已经保存");
            QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
            File tasks=existingDirectory(new File(root.path,"control-tasks"));
            File task=existingDirectory(new File(tasks,request.taskId));
            String base="background-postlaunch-recovery-"+request.requestId;
            File archive=new File(task,base+".journal.json"),receipt=new File(task,base+".json");
            MobiMindPrivateFiles.writeNew(archive,request.journalBytes());
            JSONObject saved=new JSONObject().put("schema","hepta.profile-postlaunch-recovery-commit.v1")
                    .put("source","owned_readonly_process_then_private_durable_receipt")
                    .put("task_id",request.taskId).put("generation",request.generation).put("request_id",request.requestId)
                    .put("journal_archive",archive.getName()).put("journal_sha256",request.journalSha256)
                    .put("journal_bytes",request.journalBytes().length).put("proof",proof())
                    .put("transport",new JSONObject().put("owned_process_exit_observed",true).put("exit_code",0)
                            .put("output_eof",true).put("output_complete",true).put("stdout_bytes",outputBytes)
                            .put("stdout_sha256",outputSha256).put("command_sha256",commandSha256))
                    .put("validated_elapsed_ms",validatedElapsed).put("automatic_resume",false)
                    .put("rewrites_original_task_result",false).put("broker_release_response",false);
            byte[] bytes=saved.toString(2).getBytes(StandardCharsets.UTF_8);
            MobiMindPrivateFiles.writeNew(receipt,bytes);MobiMindPrivateFiles.syncDirectory(task);
            savedReceipt=receipt;savedJournal=archive;savedSha256=HeptaAccessibilityService.sha(bytes);
            requirePersisted();root.unchanged(context);
        }
        private static File existingDirectory(File path)throws Exception{
            if(!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new java.io.IOException("恢复归档目录不是原始私有路径");
            android.system.StructStat stat=android.system.Os.lstat(path.getPath());
            if(!android.system.OsConstants.S_ISDIR(stat.st_mode)||stat.st_uid!=android.os.Process.myUid()||(stat.st_mode&0777)!=0700)
                throw new java.io.IOException("恢复归档目录缺失或归属不明");
            return path; // Never create a missing task history or alter its permissions.
        }
        void requirePersisted()throws Exception{
            if(savedReceipt==null||savedJournal==null||savedSha256==null)
                throw new java.io.IOException("恢复凭据尚未持久保存");
            byte[] receipt=MobiMindPrivateFiles.read(savedReceipt,131072,true).bytes;
            byte[] journal=MobiMindPrivateFiles.read(savedJournal,ProfilePostlaunchRecovery.MAX_JOURNAL,true).bytes;
            if(!savedSha256.equals(HeptaAccessibilityService.sha(receipt))
                    ||!request.journalSha256.equals(HeptaAccessibilityService.sha(journal))
                    ||!java.util.Arrays.equals(request.journalBytes(),journal))
                throw new java.io.IOException("已保存的恢复凭据或原租约发生变化");
        }
        String receiptSha256(){return savedSha256;}
        JSONObject evidence()throws Exception{
            requirePersisted();
            return new JSONObject().put("schema","hepta.background-reconcile.v1").put("generation",request.generation)
                    .put("cleanup_known",true).put("broker_released",false).put("broker_response",JSONObject.NULL)
                    .put("reconciliation_source",ProfilePostlaunchRecovery.SOURCE).put("postlaunch_recovery",proof())
                    .put("postlaunch_receipt_path",savedReceipt.getPath()).put("postlaunch_receipt_sha256",savedSha256)
                    .put("original_journal_sha256",request.journalSha256).put("no_late_create",true)
                    .put("display_absence_observed",true).put("automatic_resume",false);
        }
    }
    static Receipt collect(Context context,byte[] journal,BackgroundSession.ReconciliationCheck check)throws Exception{
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())
            throw new IllegalStateException("已启动租约恢复须在后台核验");
        if(check==null)throw new java.io.IOException("恢复缺少原普通 UI 会话门槛");
        check.check();LocalProbeApplication.requirePermissionPreparationIdle(context);
        int boot=Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);
        ProfilePostlaunchRecovery.Request request=ProfilePostlaunchRecovery.request(journal,android.os.Process.myUid(),
                UUID.randomUUID().toString(),SystemClock.elapsedRealtime(),boot);
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.isFile()||!apk.isAbsolute())throw new java.io.IOException("恢复核验的已安装 APK 不可用");
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / org.trillionnium.hepta.background.ProfilePostlaunchRecoveryMain"
                +" --request "+quote(request.wire());
        final Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        final ByteArrayOutputStream output=new ByteArrayOutputStream();
        final AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
        Thread reader=new Thread(()->{
            try(InputStream input=process.getInputStream()){
                byte[] block=new byte[4096];int count;
                while((count=input.read(block))!=-1){
                    if(output.size()+count>ProfilePostlaunchRecovery.MAX_OUTPUT)throw new java.io.IOException("恢复核验输出超过上限");
                    output.write(block,0,count);
                }
            }catch(Throwable error){failure.set(error);}
        },"hepta-profile-postlaunch-recovery-read");reader.setDaemon(true);reader.start();
        boolean exited=false;
        try{
            exited=process.waitFor(ProfilePostlaunchRecovery.LIMIT_MS+1500,TimeUnit.MILLISECONDS);
            if(!exited)throw new java.io.IOException("已启动租约只读核验超时");
            reader.join(500);
            if(reader.isAlive()||failure.get()!=null||process.exitValue()!=0)
                throw new java.io.IOException("已启动租约核验未得到完整成功回执");
            byte[] raw=output.toByteArray();JSONObject value=ProfilePostlaunchRecovery.object(raw);
            long now=SystemClock.elapsedRealtime();
            JSONObject verified=ProfilePostlaunchRecovery.validate(value,request,now,
                    Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1));
            check.check();
            return new Receipt(request,verified,raw,command,now);
        }finally{
            // This is only this newly owned read-only checker, never a discovered old PID/broker.
            if(!exited)process.destroy();
        }
    }
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
