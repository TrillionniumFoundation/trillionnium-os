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
import org.trillionnium.hepta.background.PublicPersonalNotesAbsenceRecovery;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Ordinary cleanup UI only: an opaque fresh Notes absence receipt. The checker
 * is read-only. Independent current absence is not normal broker RELEASED. All old task
 * files and the new request's control-session snapshot are archived byte-exact. */
final class PublicPersonalNotesRecoveryClient {
    private PublicPersonalNotesRecoveryClient(){}
    static final class Receipt {
        final PublicPersonalNotesAbsenceRecovery.Request request;
        private final String proofText,outputSha256,commandSha256;
        private final int outputBytes;
        private final long validatedElapsed;
        private final Map<String,MobiMindPrivateFiles.Read> originals;
        private final CancelledArchive cancelled;
        private File savedReceipt,savedCancelledHistory;
        private String savedSha256;
        private final Map<String,File> archives=new LinkedHashMap<String,File>();
        private Receipt(PublicPersonalNotesAbsenceRecovery.Request request,JSONObject proof,byte[] output,String command,long now,
                Map<String,MobiMindPrivateFiles.Read> originals){this(request,proof,output,command,now,originals,null);}
        private Receipt(PublicPersonalNotesAbsenceRecovery.Request request,JSONObject proof,byte[] output,String command,long now,
                Map<String,MobiMindPrivateFiles.Read> originals,CancelledArchive cancelled){
            this.cancelled=cancelled;this.request=request;proofText=proof.toString();outputSha256=HeptaAccessibilityService.sha(output);
            commandSha256=HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8));outputBytes=output.length;
            validatedElapsed=now;this.originals=new LinkedHashMap<String,MobiMindPrivateFiles.Read>(originals);
        }
        JSONObject proof()throws Exception{return PublicPersonalNotesAbsenceRecovery.object(proofText.getBytes(StandardCharsets.UTF_8));}
        void requireOriginals(boolean journalPresent)throws Exception{
            if(cancelled!=null)cancelled.requireUnchanged(request);
            if(request.releasedBeforeModel||request.initializationFailed)requireLostLaunchEntries(originals.get("result").path.getParentFile(),request.generation);
            if(request.postModelDrained)requireTaskEntries(originals.get("result").path.getParentFile(),true,request.workflowCloseFailed);
            for(Map.Entry<String,MobiMindPrivateFiles.Read> item:originals.entrySet()){
                // The typed receipt already persisted both CAS inputs before unlink. The
                // normal UI may subsequently persist its own recovered session state.
                if(!journalPresent&&("journal".equals(item.getKey())||"current_control".equals(item.getKey())))continue;
                MobiMindPrivateFiles.Read first=item.getValue();first.unchangedPath();
                byte[] actual=MobiMindPrivateFiles.read(first.path,PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true).bytes;
                if(request.cancelledAfterActions)request.requireOriginalBytes(item.getKey(),actual);
                else if(!Arrays.equals(actual,request.original(item.getKey())))throw new IOException("备忘录独立缺席恢复期间原始失败记录发生变化");
            }
        }
        void persist(Context context)throws Exception{
            if(savedReceipt!=null){requirePersisted();return;}
            requireOriginals(true);QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
            File task=existingDirectory(new File(existingDirectory(new File(root.path,"control-tasks")),request.taskId));
            if(request.cancelledAfterActions)task=cancelledRecoveryDirectory(root.path,request.requestId);
            String base="background-personal-notes-absence-"+request.requestId;JSONObject refs=new JSONObject();
            for(String name:originals.keySet()){
                File archive=new File(task,base+".original-"+name+".bin");byte[] raw=request.cancelledAfterActions?originals.get(name).bytes:request.original(name);
                createOrRequireExact(archive,raw);archives.put(name,archive);
                refs.put(name,new JSONObject().put("file",archive.getName()).put("bytes",raw.length).put("sha256",HeptaAccessibilityService.sha(raw)));
            }
            JSONObject value=new JSONObject().put("schema","hepta.personal-notes-absence-commit.v1")
                    .put("source","owned_readonly_process_then_private_durable_receipt")
                    .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                    .put("journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256)
                    .put("original_archives",refs).put("proof",proof())
                    .put("transport",new JSONObject().put("owned_process_exit_observed",true).put("exit_code",0).put("output_eof",true)
                            .put("output_complete",true).put("stdout_bytes",outputBytes).put("stdout_sha256",outputSha256).put("command_sha256",commandSha256))
                    .put("validated_elapsed_ms",validatedElapsed).put("automatic_resume",false).put("rewrites_original_task_result",false)
                    .put("historical_broker_release_observed",request.releasedBeforeModel).put("broker_release_response",false)
                    .put("current_control_sha256",request.currentControlSha256).put("control_cas_before_lease_unlink",true);
            value.put("recorded_owned_identity",request.recordedOwnedIdentity());
            if(request.cancelledAfterActions){
                File manifest=new File(task,"cancelled-history.json");byte[] bytes=request.original("cancelled_history");createOrRequireExact(manifest,bytes);savedCancelledHistory=manifest;
                value.put("cancelled_history",new JSONObject().put("file",manifest.getName()).put("bytes",bytes.length).put("sha256",HeptaAccessibilityService.sha(bytes)))
                        .put("historical_model_exit_code",143).put("historical_model_receipt_valid",false).put("historical_business_success",false);
            }
            byte[] raw=value.toString(2).getBytes(StandardCharsets.UTF_8);File receipt=new File(task,base+".json");
            createOrRequireExact(receipt,raw);MobiMindPrivateFiles.syncDirectory(task);
            savedReceipt=receipt;savedSha256=HeptaAccessibilityService.sha(raw);
            requirePersisted();requireOriginals(true);root.unchanged(context);
        }
        private static void createOrRequireExact(File file,byte[] raw)throws Exception{
            if(MobiMindPrivateFiles.exists(file)){
                if(!Arrays.equals(raw,MobiMindPrivateFiles.read(file,PublicPersonalNotesAbsenceRecovery.MAX_RECEIPT,true).bytes))
                    throw new IOException("恢复请求的已有归档不是同一字节记录");
            }else MobiMindPrivateFiles.writeNew(file,raw);
        }
        void requirePersisted()throws Exception{
            if(savedReceipt==null||savedSha256==null||archives.size()!=originals.size())throw new IOException("备忘录独立缺席恢复凭据尚未持久保存");
            byte[] raw=MobiMindPrivateFiles.read(savedReceipt,PublicPersonalNotesAbsenceRecovery.MAX_RECEIPT,true).bytes;
            if(!savedSha256.equals(HeptaAccessibilityService.sha(raw)))throw new IOException("备忘录独立缺席恢复收据发生变化");
            if(request.cancelledAfterActions&&(savedCancelledHistory==null||!Arrays.equals(request.original("cancelled_history"),MobiMindPrivateFiles.read(savedCancelledHistory,PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true).bytes)))throw new IOException("取消任务完整原件清单归档发生变化");
            for(Map.Entry<String,File> item:archives.entrySet())if(!Arrays.equals(request.cancelledAfterActions?originals.get(item.getKey()).bytes:request.original(item.getKey()),
                    MobiMindPrivateFiles.read(item.getValue(),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true).bytes))
                throw new IOException("备忘录独立缺席恢复的原始字节归档发生变化");
        }
        void requireLease(String task,String generation,String owner,long created,long expires,int boot,
                PublicOwnGroupPolicy.Scope scope,int display)throws Exception{
            if(!request.taskId.equals(task)||!request.generation.equals(generation)||!request.ownerSha256.equals(owner)
                    ||request.created!=created||request.expires!=expires||request.oldBoot!=boot||display!=request.displayId
                    ||scope==null||scope.targetUserId!=0||!scope.targetSha256.isEmpty()
                    ||!request.publicScope.wire().equals(scope.wire())||!request.publicScope.sha256.equals(scope.sha256))
                throw new IOException("备忘录独立缺席恢复凭据不属于当前个人空间原租约");
            requirePersisted();requireOriginals(false);
        }
        String receiptSha256(){return savedSha256;}
        JSONObject evidence()throws Exception{
            requirePersisted();return new JSONObject().put("schema","hepta.background-reconcile.v1").put("generation",request.generation)
                    .put("cleanup_known",true).put("broker_released",false).put("broker_response",JSONObject.NULL)
                    .put("reconciliation_source",request.source()).put("personal_notes_absence",proof())
                    .put("personal_notes_receipt_path",savedReceipt.getPath()).put("personal_notes_receipt_sha256",savedSha256)
                    .put("original_journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256)
                    .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true)
                    .put("historical_broker_release_observed",request.releasedBeforeModel)
                    .put("current_control_sha256",request.currentControlSha256).put("display_absence_observed",true).put("automatic_resume",false);
        }
    }
    static Receipt collect(Context context,MobiMindPrivateFiles.Read journal,BackgroundSession.ReconciliationCheck check)throws Exception{
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())throw new IllegalStateException("备忘录原租约恢复须在后台核验");
        if(check==null)throw new IOException("备忘录独立缺席恢复缺少普通 UI 会话门槛");check.check();LocalProbeApplication.requirePermissionPreparationIdle(context);
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);journal.unchangedPath();
        JSONObject old=PublicPersonalNotesAbsenceRecovery.object(journal.bytes);String taskId=PublicPersonalNotesAbsenceRecovery.string(old,"task_id");
        String generation=PublicPersonalNotesAbsenceRecovery.string(old,"generation");
        if(!taskId.matches("[0-9a-f]{32}")||!generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw new IOException("备忘录独立缺席恢复的原任务身份无效");
        File task=existingDirectory(new File(existingDirectory(new File(root.path,"control-tasks")),taskId));
        Map<String,MobiMindPrivateFiles.Read> actual=new LinkedHashMap<String,MobiMindPrivateFiles.Read>();actual.put("journal",journal);
        for(String[] item:new String[][]{{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},
                {"result","result.json"},{"broker_receipt","background-broker-"+generation+".json"},{"broker_output","background-broker-"+generation+".bin"}})
            actual.put(item[0],MobiMindPrivateFiles.read(new File(task,item[1]),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
        JSONObject failed=PublicPersonalNotesAbsenceRecovery.object(actual.get("result").bytes);
        boolean postModel=PublicPersonalNotesAbsenceRecovery.number(failed,"steps")==1;
        CancelledArchive cancelled=isCancelledHistory(failed)?new CancelledArchive(root.path,task,failed,actual):null;
        boolean workflowClose=postModel&&Boolean.TRUE.equals(failed.get("controller_completion_requested"));
        boolean initialization=PublicPersonalNotesAbsenceRecovery.number(old,"display_id")==-1;
        boolean lostLaunch=!initialization&&!postModel&&Boolean.FALSE.equals(PublicPersonalNotesAbsenceRecovery.object(actual.get("cleanup").bytes).get("bootstrap_dispatched"))
                &&"RELEASED".equals(PublicPersonalNotesAbsenceRecovery.object(actual.get("broker_output").bytes).optString("state"));
        if(lostLaunch||initialization){
            requireLostLaunchEntries(task,generation);
            for(String[] item:new String[][]{{"initial_binding","background-binding.json"},{"scope_binding","scope-binding.json"},{"completion_identity","completion-installed-identity.json"}})
                actual.put(item[0],MobiMindPrivateFiles.read(new File(task,item[1]),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
        }
        if(cancelled==null)requireTaskEntries(task,postModel,workflowClose);
        else cancelled.requireEntries();
        if(postModel)collectDrainedOriginals(root.path,task,failed,actual);
        if(workflowClose)collectWorkflowOriginals(task,actual);
        Map<String,byte[]> originals=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,MobiMindPrivateFiles.Read> entry:actual.entrySet())originals.put(entry.getKey(),entry.getValue().bytes);
        int uid=android.os.Process.myUid(),boot=Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);
        JSONObject controller=RecoveryControllerIdentity.read(context,uid,SystemClock.elapsedRealtime()+PublicPersonalNotesAbsenceRecovery.LIMIT_MS);
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.getPath().equals(PublicPersonalNotesAbsenceRecovery.string(controller,"source_path")))throw new IOException("备忘录独立缺席恢复的当前代码与安装身份不一致");
        MobiMindPrivateFiles.Read currentControl=MobiMindPrivateFiles.read(new File(root.path,"control-session.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true);
        JSONObject control=PublicPersonalNotesAbsenceRecovery.object(currentControl.bytes);
        if((lostLaunch||initialization||cancelled!=null)&&"interrupted".equals(control.optString("status"))){
            String relative=PublicPersonalNotesAbsenceRecovery.lostLaunchOriginArchive(control);
            File recovery=existingDirectory(new File(root.path,"session-recovery"));
            for(String[] item:new String[][]{{"origin_control",relative},{"interruption_latch","control-session.interrupted.json"}}){
                File file="origin_control".equals(item[0])?new File(recovery,new File(item[1]).getName()):new File(root.path,item[1]);
                MobiMindPrivateFiles.Read prior=MobiMindPrivateFiles.read(file,PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true);
                actual.put(item[0],prior);originals.put(item[0],prior.bytes);
            }
        }
        if(cancelled!=null){
            cancelled.startupArchive="interrupted".equals(control.optString("status"));
            originals=PublicPersonalNotesAbsenceRecovery.packCancelledInputs(originals,cancelled.history());
        }
        actual.put("current_control",currentControl);
        PublicPersonalNotesAbsenceRecovery.Request request=PublicPersonalNotesAbsenceRecovery.request(originals,currentControl.bytes,controller,uid,
                UUID.randomUUID().toString(),SystemClock.elapsedRealtime(),boot);
        if(request.postModelDrained||request.cancelledAfterActions)requireDrainedGeneration(request);
        if(cancelled!=null){cancelled.requireUnchanged(request);for(Map.Entry<String,MobiMindPrivateFiles.Read> entry:actual.entrySet())request.requireOriginalBytes(entry.getKey(),entry.getValue().bytes);}
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / org.trillionnium.hepta.background.PublicPersonalNotesAbsenceMain --request "+quote(request.wire());
        // The complete command must also fit the unchanged root proc-census bound.
        if(command.getBytes(StandardCharsets.UTF_8).length>=60000)throw new IOException("备忘录独立缺席恢复命令超过完整进程核验上限");
        check.check();if(cancelled==null)requireTaskEntries(task,postModel,workflowClose);else cancelled.requireUnchanged(request);if(lostLaunch||initialization)requireLostLaunchEntries(task,generation);for(MobiMindPrivateFiles.Read first:actual.values())first.unchangedPath();
        final Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        final Capture capture=new Capture(process.getInputStream());Thread reader=new Thread(capture,"hepta-personal-notes-recovery-read");reader.setDaemon(true);reader.start();
        boolean exited=false;
        try{
            process.getOutputStream().close();long left=request.deadline-SystemClock.elapsedRealtime();
            if(left<=0||!process.waitFor(left,TimeUnit.MILLISECONDS))throw new IOException("备忘录原租约只读核验超时");exited=true;
            left=request.deadline-SystemClock.elapsedRealtime();if(left>0)reader.join(left);
            if(reader.isAlive()||capture.failure!=null||!capture.eof||process.exitValue()!=0)throw new IOException("备忘录原租约核验没有完整成功回执");
            byte[] output=capture.bytes;JSONObject verified=PublicPersonalNotesAbsenceRecovery.validate(PublicPersonalNotesAbsenceRecovery.object(output),request,
                    SystemClock.elapsedRealtime(),Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1));
            if(!PublicPersonalNotesAbsenceRecovery.same(controller,RecoveryControllerIdentity.read(context,uid,request.deadline)))throw new IOException("备忘录独立缺席恢复期间当前安装代码发生变化");
            check.check();if(cancelled==null)requireTaskEntries(task,postModel,workflowClose);else cancelled.requireUnchanged(request);Receipt receipt=new Receipt(request,verified,output,command,SystemClock.elapsedRealtime(),actual,cancelled);
            receipt.requireOriginals(true);request.requireFence(SystemClock.elapsedRealtime(),Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1));
            return receipt;
        }catch(Exception error){
            // A failed check never becomes cleanup authority. Retain this new attempt for diagnosis.
            try{recordFailedAttempt(context,request,capture,reader,process,exited,command,error);}
            catch(Exception archiveFailure){error.addSuppressed(archiveFailure);}
            throw error;
        }finally{if(!exited)process.destroy();}
    }
    private static void requireLostLaunchEntries(File task,String generation)throws Exception{
        String[] files=task.list();if(files==null)throw new IOException("无法完整读取备忘录启动前后的任务记录");
        java.util.Set<String> expected=new java.util.HashSet<String>(Arrays.asList("owner.json","background-binding.json","background-bootstrap.json",
                "background-cleanup.json","result.json","scope-binding.json","completion-installed-identity.json",
                "background-broker-"+generation+".json","background-broker-"+generation+".bin"));
        String checker="background-personal-notes-absence-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
        for(String name:files){
            if(expected.remove(name))continue;
            if(name.matches(checker+"(?:[.]json|[.]attempt[.]json|[.]checker-output[.]bin|[.]original-(?:journal|owner|bootstrap|cleanup|result|broker_receipt|broker_output|initial_binding|scope_binding|completion_identity|origin_control|interruption_latch|current_control)[.]bin)"))continue;
            throw new IOException("备忘录启动恢复发现额外的任务记录");
        }
        if(!expected.isEmpty())throw new IOException("备忘录启动恢复缺少原始任务记录");
    }
    private static void requireTaskEntries(File task,boolean postModel)throws Exception{
        String[] leaves=task.list();if(leaves==null)throw new IOException("备忘录独立缺席恢复的原任务目录不可读");
        java.util.Set<String> singleStep=new java.util.HashSet<String>(Arrays.asList("step-01-before.json","step-01-budget-0.json",
                "step-01-model-0.json","step-01-action.json","step-01-failed-after-diagnostic.json","fixed-intent-01-attempt.json"));
        for(String name:leaves)if(name.matches("step-[0-9]+-.*")||name.startsWith("ime-submit-")||name.startsWith("fixed-intent-")
                ||name.startsWith("native-app-")||name.startsWith("controller-completion-")){
            if(!postModel||!singleStep.contains(name))throw new IOException("备忘录独立缺席恢复发现未覆盖的模型或业务步骤");
        }
    }
    private static void requireTaskEntries(File task,boolean postModel,boolean workflowClose)throws Exception{
        if(!workflowClose){requireTaskEntries(task,postModel);return;}
        if(!postModel)throw new IOException("备忘录工作流恢复缺少单步模型记录");
        String[] leaves=task.list();if(leaves==null)throw new IOException("备忘录工作流恢复的原任务目录不可读");
        java.util.Set<String> covered=new java.util.HashSet<String>(Arrays.asList(
                "step-01-before.json","step-01-budget-0.json","step-01-model-0.json","step-01-action.json","fixed-intent-01-attempt.json",
                "step-01-after.json","step-01-notes-readiness-result.json","step-01-notes-workflow-grant-consumed.json",
                "step-01-notes-workflow-child-1-planned.json","step-01-notes-workflow-child-2-planned.json",
                "step-01-notes-workflow-observation-1.json","step-01-notes-workflow-observation-2.json",
                "step-01-notes-workflow-observation-3.json","step-01-notes-workflow-observation-4.json","step-01-notes-workflow-result.json",
                "step-01-tool-child-01-before.json","step-01-tool-child-01-action.json","step-01-tool-child-01-after.json","step-01-tool-child-01-proof.json",
                "step-01-tool-child-02-before.json","step-01-tool-child-02-action.json","step-01-tool-child-02-after.json","step-01-tool-child-02-proof.json",
                "controller-completion-candidate.json"));
        for(String name:leaves)if(name.matches("step-[0-9]+-.*")||name.startsWith("ime-submit-")||name.startsWith("fixed-intent-")
                ||name.startsWith("native-app-")||name.startsWith("controller-completion-")){
            if(!covered.contains(name))throw new IOException("备忘录工作流恢复发现未覆盖的模型或业务步骤");
        }
    }
    private static void collectWorkflowOriginals(File task,Map<String,MobiMindPrivateFiles.Read> actual)throws Exception{
        for(String[] item:new String[][]{{"workflow_result","step-01-notes-workflow-result.json"},{"workflow_grant","step-01-notes-workflow-grant-consumed.json"},
                {"child_1_action","step-01-tool-child-01-action.json"},{"child_2_action","step-01-tool-child-02-action.json"},
                {"child_1_proof","step-01-tool-child-01-proof.json"},{"child_2_proof","step-01-tool-child-02-proof.json"},
                {"completion_candidate","controller-completion-candidate.json"},{"completion_identity","completion-installed-identity.json"}})
            actual.put(item[0],MobiMindPrivateFiles.read(new File(task,item[1]),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
    }
    private static String id(JSONObject object,String key)throws Exception{
        String value=PublicPersonalNotesAbsenceRecovery.string(object,key);
        if(!value.matches("[0-9a-f]{32}"))throw new IOException("备忘录已退出模型的原件身份无效");return value;
    }
    private static void collectDrainedOriginals(File root,File task,JSONObject failed,Map<String,MobiMindPrivateFiles.Read> actual)throws Exception{
        for(String[] item:new String[][]{{"step_model","step-01-model-0.json"},{"step_action","step-01-action.json"},{"fixed_intent_attempt","fixed-intent-01-attempt.json"}})
            actual.put(item[0],MobiMindPrivateFiles.read(new File(task,item[1]),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
        JSONObject step=PublicPersonalNotesAbsenceRecovery.object(actual.get("step_model").bytes);
        String run=id(step,"run_id"),generation=id(failed.getJSONObject("model_session"),"worker_generation");
        if(run.equals(generation))throw new IOException("备忘录模型请求与工作进程目录重合");
        File runs=existingDirectory(new File(root,"runs")),request=existingDirectory(new File(runs,run)),worker=existingDirectory(new File(runs,generation));
        actual.put("model_request_receipt",MobiMindPrivateFiles.read(new File(request,"app-receipt.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
        actual.put("model_session_receipt",MobiMindPrivateFiles.read(new File(worker,"app-session-receipt.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
        actual.put("native_session_receipt",MobiMindPrivateFiles.read(new File(worker,"native-session-result.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
        JSONObject session=PublicPersonalNotesAbsenceRecovery.object(actual.get("model_session_receipt").bytes),cleanup=session.getJSONObject("worker_generation_cleanup");
        String nonce=id(cleanup,"cleanup_nonce");
        File identity=new File(worker,"worker-generation.identity"),nativeReceipt=new File(worker,"generation-cleanup-"+nonce+".json");
        // Receipt paths are compared with derived owned paths; they are never used
        // as input paths and never widen the read-only recovery file set.
        if(!identity.getPath().equals(PublicPersonalNotesAbsenceRecovery.string(cleanup,"identity_file"))
                ||!nativeReceipt.getPath().equals(PublicPersonalNotesAbsenceRecovery.string(cleanup,"native_receipt_file")))
            throw new IOException("备忘录模型退出原件不属于固定私有工作目录");
        actual.put("generation_identity",MobiMindPrivateFiles.read(identity,WorkerGenerationProof.IDENTITY_LIMIT,true));
        actual.put("generation_cleanup_receipt",MobiMindPrivateFiles.read(nativeReceipt,WorkerGenerationProof.RECEIPT_LIMIT,true));
    }
    static void requireDrainedGeneration(PublicPersonalNotesAbsenceRecovery.Request request)throws Exception{
        if(!request.postModelDrained&&!request.cancelledAfterActions)throw new IOException("备忘录退出证明不属于已执行恢复");
        JSONObject session=PublicPersonalNotesAbsenceRecovery.object(request.original("model_session_receipt")),g=session.getJSONObject("worker_generation_cleanup");
        JSONObject nativeReceipt=PublicPersonalNotesAbsenceRecovery.object(request.original("generation_cleanup_receipt"));
        WorkerGenerationProof.Expected expected=new WorkerGenerationProof.Expected(request.taskId,id(session,"worker_generation"),id(g,"scope_token"),
                PublicPersonalNotesAbsenceRecovery.string(g,"boot_id"),request.ownerUid,
                PublicPersonalNotesAbsenceRecovery.number(g,"app_pid"),PublicPersonalNotesAbsenceRecovery.number(g,"app_start_ticks"));
        WorkerGenerationProof.Identity identity=WorkerGenerationProof.identity(request.original("generation_identity"),expected);
        String nonce=id(g,"cleanup_nonce");
        JSONObject verified=WorkerGenerationProof.bindCleanup(identity,nonce,
                PublicPersonalNotesAbsenceRecovery.number(g,"submitted_monotonic_ns"),PublicPersonalNotesAbsenceRecovery.number(g,"deadline_monotonic_ns"),
                PublicPersonalNotesAbsenceRecovery.number(session,"finisher_submitted_monotonic_ns"),PublicPersonalNotesAbsenceRecovery.number(session,"finisher_deadline_monotonic_ns"),
                nativeReceipt,Boolean.TRUE.equals(g.get("helper_exit_observed")),Integer.valueOf((int)PublicPersonalNotesAbsenceRecovery.number(g,"helper_exit_code")),
                !Boolean.FALSE.equals(g.get("helper_force_destroy_sent")));
        if(!PublicPersonalNotesAbsenceRecovery.same(verified,g.getJSONObject("native_cleanup"))
                ||WorkerGenerationProof.boundForceAttempts(identity,nonce,nativeReceipt)!=0
                ||PublicPersonalNotesAbsenceRecovery.number(nativeReceipt,"term_attempts")!=0
                ||PublicPersonalNotesAbsenceRecovery.number(nativeReceipt,"kill_attempts")!=0||nativeReceipt.getJSONArray("targets").length()!=0)
            throw new IOException("备忘录原模型工作进程没有完整的无强制退出证明");
    }
    private static void recordFailedAttempt(Context context,PublicPersonalNotesAbsenceRecovery.Request request,Capture capture,
            Thread reader,Process process,boolean exited,String command,Exception error)throws Exception{
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
        File task=existingDirectory(new File(existingDirectory(new File(root.path,"control-tasks")),request.taskId));
        if(request.cancelledAfterActions)task=cancelledRecoveryDirectory(root.path,request.requestId);
        String base="background-personal-notes-absence-"+request.requestId;byte[] output=reader.isAlive()?null:capture.bytes;
        JSONObject value=new JSONObject().put("schema","hepta.personal-notes-absence-failed-attempt.v1")
                .put("request_id",request.requestId).put("task_id",request.taskId).put("generation",request.generation)
                .put("journal_sha256",request.journalSha256).put("originals_sha256",request.originalsSha256)
                .put("original_inputs",request.inputHashes()).put("current_controller",request.controller()).put("current_control_sha256",request.currentControlSha256)
                .put("command_sha256",HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8)))
                .put("owned_process_exit_observed",exited).put("exit_code",exited?process.exitValue():JSONObject.NULL)
                .put("reader_alive",reader.isAlive()).put("output_eof",capture.eof)
                .put("output_complete",!reader.isAlive()&&capture.eof&&capture.failure==null)
                .put("read_failure_class",capture.failure==null?JSONObject.NULL:capture.failure.getClass().getName())
                .put("error_class",error.getClass().getName()).put("cleanup_known",false).put("lease_retired",false)
                .put("automatic_resume",false).put("rewrites_original_task_result",false);
        if(output!=null){File raw=new File(task,base+".checker-output.bin");MobiMindPrivateFiles.writeNew(raw,output);
            value.put("output_file",raw.getName()).put("output_bytes",output.length).put("output_sha256",HeptaAccessibilityService.sha(output));
            if(capture.eof&&capture.failure==null){try{JSONObject diagnostic=PublicPersonalNotesAbsenceRecovery.object(output);
                String code=PublicPersonalNotesAbsenceRecovery.string(diagnostic,"error");
                if(request.proofSchema().equals(diagnostic.optString("schema"))&&request.requestId.equals(diagnostic.optString("request_id"))
                        &&Boolean.FALSE.equals(diagnostic.get("cleanup_known"))&&code.matches("[A-Z0-9_]{1,96}"))value.put("checker_error",code);
            }catch(Exception notAnErrorRecord){/* Retain actual bytes without treating them as a proof. */}}
        }
        MobiMindPrivateFiles.writeNew(new File(task,base+".attempt.json"),value.toString(2).getBytes(StandardCharsets.UTF_8));
        MobiMindPrivateFiles.syncDirectory(task);root.unchanged(context);
    }
    private static boolean isCancelledHistory(JSONObject failed)throws Exception{
        long steps=PublicPersonalNotesAbsenceRecovery.number(failed,"steps");JSONObject model=failed.getJSONObject("model_session");
        return steps>=2&&steps<=24&&PublicPersonalNotesAbsenceRecovery.number(failed,"stop_requested_elapsed_ms")>0
                &&Boolean.TRUE.equals(model.get("process_started"))&&Boolean.TRUE.equals(model.get("process_exit_observed"))
                &&Long.valueOf(143).equals(Long.valueOf(PublicPersonalNotesAbsenceRecovery.number(model,"exit_code")))&&Boolean.FALSE.equals(model.get("receipt_valid"));
    }
    private static String cancelledKey(int ordinal,String suffix){return String.format(java.util.Locale.ROOT,"cancelled_%s_%02d",suffix,ordinal);}
    /** Full task-directory witnesses stay byte-exact. Only the nine complete action
     * JSON values lose indentation in the bounded request; no semantic field is dropped. */
    private static final class CancelledArchive {
        final File task;final int count;final Map<String,MobiMindPrivateFiles.Read> taskFiles=new java.util.TreeMap<String,MobiMindPrivateFiles.Read>();
        final java.util.List<MobiMindPrivateFiles.Read> requests=new java.util.ArrayList<MobiMindPrivateFiles.Read>();
        final java.util.List<String> runs=new java.util.ArrayList<String>();boolean startupArchive;
        CancelledArchive(File root,File task,JSONObject result,Map<String,MobiMindPrivateFiles.Read> actual)throws Exception{
            this.task=task;count=(int)PublicPersonalNotesAbsenceRecovery.number(result,"steps")-1;
            String[] entries=task.list();if(entries==null||entries.length>256)throw new IOException("取消任务的完整原件目录不可读");
            Arrays.sort(entries);long total=0;
            for(String name:entries){
                if(!name.matches("[a-zA-Z0-9_.-]{1,128}"))throw new IOException("取消任务原件路径无效");
                MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(new File(task,name),PublicPersonalNotesAbsenceRecovery.MAX_RECEIPT,true);
                total+=read.bytes.length;if(total>8388608)throw new IOException("取消任务的完整原件超过上限");taskFiles.put(name,read);
            }
            File runsRoot=existingDirectory(new File(root,"runs"));String worker=id(result.getJSONObject("model_session"),"worker_generation");
            for(int i=1;i<=count;i++){
                String action=PublicPersonalNotesAbsenceRecovery.cancelledStepName(i,"action"),model=PublicPersonalNotesAbsenceRecovery.cancelledStepName(i,"model-0");
                MobiMindPrivateFiles.Read a=taskFiles.get(action),m=taskFiles.get(model);if(a==null||m==null)throw new IOException("取消任务缺少完整动作或模型原件");
                actual.put(cancelledKey(i,"action"),a);actual.put(cancelledKey(i,"model"),m);
                String run=id(PublicPersonalNotesAbsenceRecovery.object(m.bytes),"run_id");if(run.equals(worker)||runs.contains(run))throw new IOException("取消任务模型请求身份重复");runs.add(run);
                MobiMindPrivateFiles.Read request=MobiMindPrivateFiles.read(new File(existingDirectory(new File(runsRoot,run)),"app-receipt.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true);
                requests.add(request);actual.put(cancelledKey(i,"request"),request);
            }
            File generation=existingDirectory(new File(runsRoot,worker));
            actual.put("model_session_receipt",MobiMindPrivateFiles.read(new File(generation,"app-session-receipt.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
            actual.put("native_session_receipt",MobiMindPrivateFiles.read(new File(generation,"native-session-result.json"),PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true));
            JSONObject session=PublicPersonalNotesAbsenceRecovery.object(actual.get("model_session_receipt").bytes),cleanup=session.getJSONObject("worker_generation_cleanup");String nonce=id(cleanup,"cleanup_nonce");
            File identity=new File(generation,"worker-generation.identity"),receipt=new File(generation,"generation-cleanup-"+nonce+".json");
            if(!identity.getPath().equals(PublicPersonalNotesAbsenceRecovery.string(cleanup,"identity_file"))||!receipt.getPath().equals(PublicPersonalNotesAbsenceRecovery.string(cleanup,"native_receipt_file")))
                throw new IOException("取消任务模型终止原件不属于原代际目录");
            actual.put("generation_identity",MobiMindPrivateFiles.read(identity,WorkerGenerationProof.IDENTITY_LIMIT,true));
            actual.put("generation_cleanup_receipt",MobiMindPrivateFiles.read(receipt,WorkerGenerationProof.RECEIPT_LIMIT,true));
        }
        JSONObject history()throws Exception{
            org.json.JSONArray files=new org.json.JSONArray(),receipts=new org.json.JSONArray();
            for(Map.Entry<String,MobiMindPrivateFiles.Read> entry:taskFiles.entrySet())files.put(new org.json.JSONArray().put(entry.getKey()).put(entry.getValue().bytes.length).put(HeptaAccessibilityService.sha(entry.getValue().bytes)));
            for(int i=0;i<requests.size();i++){byte[] raw=requests.get(i).bytes;receipts.put(new org.json.JSONArray().put(runs.get(i)).put(raw.length).put(HeptaAccessibilityService.sha(raw)));}
            return new JSONObject().put("schema","hepta.personal-notes-cancelled-history.v1").put("completed_actions",count).put("startup_archive",startupArchive)
                    .put("task_files",files).put("request_receipts",receipts);
        }
        void requireEntries()throws Exception{
            String[] names=task.list();if(names==null||!new java.util.TreeSet<String>(Arrays.asList(names)).equals(taskFiles.keySet()))throw new IOException("取消任务恢复期间原件成员发生变化");
        }
        void requireUnchanged(PublicPersonalNotesAbsenceRecovery.Request request)throws Exception{
            requireEntries();
            if(!PublicPersonalNotesAbsenceRecovery.same(history(),PublicPersonalNotesAbsenceRecovery.object(request.original("cancelled_history"))))throw new IOException("取消任务完整原件清单发生变化");
            for(Map.Entry<String,MobiMindPrivateFiles.Read> entry:taskFiles.entrySet()){
                MobiMindPrivateFiles.Read first=entry.getValue();first.unchangedPath();byte[] current=MobiMindPrivateFiles.read(first.path,PublicPersonalNotesAbsenceRecovery.MAX_RECEIPT,true).bytes;
                request.requireTaskWitness(entry.getKey(),current);
            }
            for(int i=0;i<requests.size();i++){MobiMindPrivateFiles.Read first=requests.get(i);first.unchangedPath();
                request.requireOriginalBytes(cancelledKey(i+1,"request"),MobiMindPrivateFiles.read(first.path,PublicPersonalNotesAbsenceRecovery.MAX_ORIGINAL,true).bytes);}
        }
    }
    private static File cancelledRecoveryDirectory(File files,String request)throws Exception{
        File recovery=MobiMindPrivateFiles.directory(new File(files,"session-recovery"),false);
        return MobiMindPrivateFiles.directory(new File(recovery,"notes-cancelled-absence-"+request),true);
    }

    private static File existingDirectory(File path)throws Exception{
        if(!path.getAbsoluteFile().equals(path.getCanonicalFile()))throw new IOException("备忘录独立缺席恢复归档路径不是原始私有目录");
        android.system.StructStat s=android.system.Os.lstat(path.getPath());
        if(!android.system.OsConstants.S_ISDIR(s.st_mode)||s.st_uid!=android.os.Process.myUid()||(s.st_mode&0777)!=0700)
            throw new IOException("备忘录独立缺席恢复的既有任务目录缺失或归属不明");return path;
    }
    private static final class Capture implements Runnable{
        private final InputStream input;volatile byte[] bytes;volatile Throwable failure;volatile boolean eof;
        Capture(InputStream input){this.input=input;}
        public void run(){ByteArrayOutputStream output=new ByteArrayOutputStream();try(InputStream owned=input){
            byte[] block=new byte[4096];int count;while((count=owned.read(block))!=-1){if(output.size()+count>PublicPersonalNotesAbsenceRecovery.MAX_OUTPUT)
                throw new IOException("备忘录独立缺席恢复输出超过上限");output.write(block,0,count);}eof=true;
        }catch(Throwable failed){failure=failed;}finally{bytes=output.toByteArray();}}
    }
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
