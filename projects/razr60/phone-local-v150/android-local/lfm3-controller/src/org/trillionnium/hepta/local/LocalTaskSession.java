package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.AtomicFile;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONTokener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/** Application lifetime session; the Accessibility service owns the controller itself. */
public final class LocalTaskSession {
    public interface Listener { void onSessionChanged(); }
    private final Context context;
    private final LocalModelEngine engine;
    private final Handler main = new Handler(Looper.getMainLooper());
    private WeakReference<Listener> ui = new WeakReference<>(null);
    private volatile LocalTaskController controller;
    private volatile HeptaAccessibilityService controllerService;
    private Runnable pendingStart;
    private String state = "输入任务，然后点击开始任务。", log = "", taskId, origin, instructionSha, nonceSha;
    private TaskAuthorization taskAuthorization;
    private LocalTaskController.TaskResult lastResult;
    private String expectedScopeSha,actualScopeSha;
    private volatile boolean pending, blocked, recovering;
    private volatile long generation;
    private long recoveryIgnoredGeneration=-1;
    private final ExecutorService recoveryWorker=Executors.newSingleThreadExecutor();
    private RecoveryJournalTransaction.Proof acknowledgedSession;
    private static final int SESSION_LIMIT = 65536;
    private static final String INTERRUPTION_LATCH = "control-session.interrupted.json";
    private JSONObject startupRecovery;

    LocalTaskSession(Context context, LocalModelEngine engine) {
        this.context=context.getApplicationContext(); this.engine=engine;
        recoverPreviousSession();
    }
    public void bind(Listener listener) { ui = new WeakReference<>(listener); publish(); }
    public void unbind(Listener listener) { if (ui.get()==listener) ui.clear(); }
    public boolean isRunning() { return pending || (controller!=null && controller.isRunning()); }
    public boolean isBlocked() { return blocked; }
    public boolean isRecovering() { return recovering; }
    public boolean canAcknowledgeInterruption(){
        return !recovering&&!isRunning()&&((LocalProbeApplication)context).canAcknowledgeControlRecovery();
    }
    public String state() { return state; }
    public String log() { return log; }
    public String taskId() { return taskId; }
    public LocalTaskController.TaskResult lastResult() { return lastResult; }

    /** Caller first reserves this one session, then moves its Activity behind the target window. */
    public boolean schedule(final String owner,String source,String testNonceSha,long delayMillis){return schedule(owner,source,testNonceSha,null,delayMillis);}
    public boolean schedule(final String owner, String source, String testNonceSha, final String expectedScopeSha256, long delayMillis) {
        return schedule(owner,source,testNonceSha,expectedScopeSha256,TaskAuthorization.parse(owner),delayMillis);
    }
    public boolean schedule(final String owner,String source,String testNonceSha,final String expectedScopeSha256,final TaskAuthorization authorization,long delayMillis){
        QualificationScope.expected(expectedScopeSha256);
        TaskAuthorization.require(authorization!=null,"任务授权合同缺失");authorization.requireOwner(owner);
        if (Looper.myLooper()!=Looper.getMainLooper()) throw new IllegalStateException("schedule must run on main thread");
        if (isRunning() || engine.isBusy() || blocked) return false;
        final HeptaAccessibilityService service=HeptaAccessibilityService.connected();
        if (service==null) throw new IllegalStateException("请先启用 Hepta 本地操作无障碍服务");
        if (owner==null || owner.trim().isEmpty()) throw new IllegalArgumentException("请先输入要完成的手机任务");
        if (controllerService!=service) { controller=service.taskController(engine); controllerService=service; }
        final long epoch=++generation;
        origin=source; instructionSha=HeptaAccessibilityService.sha(owner.getBytes(StandardCharsets.UTF_8)); nonceSha=testNonceSha;
        taskAuthorization=authorization;
        expectedScopeSha=expectedScopeSha256;actualScopeSha=null;
        taskId=null;lastResult=null;log="";pending=true;setState("任务已准备，正在等待前台画面稳定…\n"+authorization.summary());
        // A durable non-terminal reservation must precede any controller or model start.
        if(!persist("pending",true)){pending=false;blocked=true;publish();return false;}
        pendingStart=new Runnable(){public void run(){
            pendingStart=null;
            if(!pending)return;
            pending=false;
            if(HeptaAccessibilityService.connected()!=service){setState("无障碍服务已断开，任务未启动");persist("not_started",true);return;}
            try{
                boolean started=controller.start(owner,expectedScopeSha256,authorization,new LocalTaskController.Listener(){
                    public void onState(String value){if(epoch>recoveryIgnoredGeneration&&epoch==generation&&!pending)receiveState(value);}
                    public void onFinished(LocalTaskController.TaskResult result){
                        if(epoch<=recoveryIgnoredGeneration)return;
                        if(epoch==generation)receiveFinished(result);
                        else if(!result.cleanupKnown){
                            blocked=true;pending=false;generation++;
                            if(pendingStart!=null)main.removeCallbacks(pendingStart);pendingStart=null;
                            if(controller!=null&&controller.isRunning())controller.stop();
                            engine.cancelActive();
                            setState("上一次任务退出状态未知，已停止接受新任务");persist("blocked",false);
                        }
                    }
                });
                if(!started){setState("已有任务正在运行或退出状态待确认，任务未启动");persist("not_started",true);return;}
                taskId=controller.currentTaskId();setState("任务已启动，正在观察手机…");persist("running",true);
            }catch(Exception error){setState("无法启动："+HeptaAccessibilityService.message(error));persist("not_started",true);}
            publish();
        }};
        main.postDelayed(pendingStart,Math.max(350,delayMillis));
        return true;
    }
    public void stop() {
        if(pending){pending=false;generation++;if(pendingStart!=null)main.removeCallbacks(pendingStart);pendingStart=null;setState("已停止，任务尚未开始操作");persist("cancelled_before_start",true);}
        if(controller!=null && controller.isRunning())controller.stop();
        publish();
    }
    private void receiveState(String value) { setState(value); persist("running",true); }
    private void receiveFinished(LocalTaskController.TaskResult result) {
        lastResult=result;taskId=result.taskId;pending=false;blocked=!result.cleanupKnown;
        expectedScopeSha=result.expectedScopeSha256;actualScopeSha=result.actualScopeSha256;
        setState(result.summary);persist(result.status,result.cleanupKnown);
    }
    private void setState(String value) {
        state=value;log=log+value+"\n";
        if(log.length()>16000)log=log.substring(log.length()-16000);
        publish();
    }
    private void publish() { Listener listener=ui.get();if(listener!=null)listener.onSessionChanged(); }

    /** The only caller is the positive button of MainActivity's visible owner confirmation. */
    public void acknowledgeInterruptionFromOwnerButton(){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("owner confirmation must run on main thread");
        if(!canAcknowledgeInterruption())throw new IllegalStateException("会话、其它诊断或模型槽状态不允许确认中断");
        final LocalProbeApplication application=(LocalProbeApplication)context;
        final LocalTaskController oldController=controller;
        final HeptaAccessibilityService service=HeptaAccessibilityService.connected();
        if(controllerService!=null&&controllerService!=service)throw new IllegalStateException("原控制器服务身份已变化，请正常重启应用后再确认");
        if(service!=null&&!service.recoveryControllerIdle(oldController))throw new IllegalStateException("屏幕观察或原控制器尚未空闲");
        if(service==null&&oldController!=null)throw new IllegalStateException("原控制器服务不可核验");
        final long retired=generation;
        recoveryIgnoredGeneration=Math.max(recoveryIgnoredGeneration,retired);
        final long epoch=++generation;
        recovering=true;state="正在保存中断记录并核验本机可见进程；旧任务不会恢复。";publish();
        final LocalModelEngine.RecoveryReservation[] reservation=new LocalModelEngine.RecoveryReservation[1];
        try{
            RecoveryDispatch.start(new RecoveryDispatch.LeaseFactory(){public RecoveryDispatch.Lease acquire(){
                    reservation[0]=application.reserveControlRecovery();return reservation[0];
                }},recoveryWorker,new Executor(){public void execute(Runnable runnable){
                    if(!main.post(runnable))throw new RejectedExecutionException("main handler unavailable");
                }},new RecoveryDispatch.Work<RecoveryJournalTransaction.Proof>(){public RecoveryJournalTransaction.Proof run()throws Exception{
                    final RecoveryJournalTransaction.Check check=new RecoveryJournalTransaction.Check(){public void check()throws Exception{
                        if(!recovering||generation!=epoch||pending||controller!=oldController
                                ||(oldController!=null&&oldController.isRunning())
                                ||reservation[0]==null||reservation[0].isCancellationRequested())
                            throw new IOException("recovery owner or shared reservation changed");
                    }};
                    check.check();RecoveryJournalStore store=new RecoveryJournalStore(context);
                    try(RecoveryJournalStore.Lock held=store.lock()){
                        List<RecoveryQuiescence.Sample> samples=RecoveryProcessInventory.awaitInitial(context);check.check();
                        RecoveryJournalTransaction.Proof proof=RecoveryJournalTransaction.acknowledge(store,android.os.Process.myUid(),android.os.Process.myPid(),
                            reservation[0].transactionId(),UUID.randomUUID().toString().replace("-",""),
                            System.currentTimeMillis(),samples,check,
                            new RecoveryJournalTransaction.FreshSample(){public RecoveryQuiescence.Sample capture()throws Exception{
                                check.check();return RecoveryProcessInventory.capture(context);
                            }},new RecoveryJournalTransaction.IdleFactory(){public byte[] create(RecoveryJournalTransaction.Acknowledgement a)throws Exception{
                                return newIdleJournal(a).toString(2).getBytes(StandardCharsets.UTF_8);
                            }});
                        byte[] active=store.read(RecoveryJournalTransaction.ACTIVE);
                        if(active==null||!proof.newIdleSha256.equals(RecoveryJournalTransaction.sha(active))
                                ||!SessionRecovery.evaluate(fieldsOf(parseSessionJson(active)),android.os.Process.myUid(),false,proof).allowNewTask)
                            throw new IOException("new idle journal did not pass the actual startup policy");
                        check.check();return proof;
                    }
                }},new RecoveryDispatch.Completion<RecoveryJournalTransaction.Proof>(){
                    public void finished(RecoveryJournalTransaction.Proof proof,Exception failure){
                        try{
                            if(failure!=null)throw failure;
                            if(generation!=epoch||!recovering||reservation[0].isCancellationRequested()
                                    ||controller!=oldController||HeptaAccessibilityService.connected()!=service)
                                throw new IOException("recovery owner changed before UI completion");
                            application.completeControlRecovery(reservation[0],proof,new Runnable(){public void run(){
                                installAcknowledgedSession(proof,oldController,service);
                            }});
                        }catch(Exception error){
                            blocked=true;state="尚未解除中断："+HeptaAccessibilityService.message(error)+"。原记录已保留；可核验空闲后再次由你确认。";
                            log=log+state+"\n";
                        }finally{
                            recovering=false;
                            // Runs after RecoveryDispatch releases the slot, so the fresh UI is not left disabled.
                            main.post(new Runnable(){public void run(){publish();}});
                        }
                    }
                });
        }catch(Exception error){recovering=false;blocked=true;setState("无法开始中断确认："+HeptaAccessibilityService.message(error));}
    }

    private void installAcknowledgedSession(RecoveryJournalTransaction.Proof proof,
            LocalTaskController oldController,HeptaAccessibilityService service){
        try{
            RecoveryJournalStore store=new RecoveryJournalStore(context);
            try(RecoveryJournalStore.Lock held=store.lock()){
                byte[] active=store.read(RecoveryJournalTransaction.ACTIVE);
                RecoveryJournalTransaction.Proof current=RecoveryJournalTransaction.verifyReady(store,android.os.Process.myUid(),
                        proof.acknowledgement.transactionId,active);
                if(!current.commitSha256.equals(proof.commitSha256)||!current.newIdleSha256.equals(proof.newIdleSha256)
                        ||!SessionRecovery.evaluate(fieldsOf(parseSessionJson(active)),android.os.Process.myUid(),false,current).allowNewTask)
                    throw new IOException("new idle proof changed before owner completion");
                if(controller!=oldController||HeptaAccessibilityService.connected()!=service||pending
                        ||(oldController!=null&&oldController.isRunning()))throw new IOException("controller owner changed during acknowledgement");
                if(service!=null)service.retireControllerAfterAcknowledgement(oldController,current);
                acknowledgedSession=current;controller=null;controllerService=null;pending=false;pendingStart=null;
                taskId=null;origin=null;instructionSha=null;nonceSha=null;taskAuthorization=null;lastResult=null;startupRecovery=null;expectedScopeSha=null;actualScopeSha=null;
                blocked=false;state="已建立新的空闲会话，可开始新任务。旧任务仍记为中断，原进程退出与清理状态仍未知。";
                log=log+state+"\n没有自动启动、恢复或重放任何任务。\n";
                if(log.length()>16000)log=log.substring(log.length()-16000);
            }
        }catch(Exception failure){throw new IllegalStateException("无法完成新会话身份核验",failure);}
    }

    /** Called only by the Application after this recovery lease actually retained its barrier. */
    void recoveryLeaseRetained(){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("recovery close notification must run on main thread");
        blocked=true;recovering=false;
        state="本次会话确认未完成，模型槽仍保持阻塞；旧记录已保留，可再次由你确认。";
        try{
            File latch=new File(context.getFilesDir().getCanonicalFile(),INTERRUPTION_LATCH);
            if(!recordExists(latch)){
                JSONObject reason=new JSONObject().put("schema","hepta.recovery-handoff-retained.v1")
                        .put("decision","blocked_recovery_handoff_unreleased").put("old_native_cleanup","unknown")
                        .put("automatic_resume",false).put("native_cleanup_independently_observed",false);
                if(acknowledgedSession!=null)reason.put("acknowledgement_transaction_id",acknowledgedSession.acknowledgement.transactionId);
                // The completed idle/archive bytes are left intact; this separate barrier wins at startup.
                createInterruptionLatch(latch,reason);
            }
        }catch(Exception failure){state=state+" 阻塞凭据写入未确认，仍不接受新任务。";}
        log=log+state+"\n";if(log.length()>16000)log=log.substring(log.length()-16000);
        // App reconciliation must finish retaining its barrier before a refresh can query eligibility again.
        main.post(new Runnable(){public void run(){publish();}});
    }

    private static JSONObject newIdleJournal(RecoveryJournalTransaction.Acknowledgement a)throws Exception{
        return new JSONObject().put("schema","hepta.local-session.v1").put("status",RecoveryJournalTransaction.IDLE_STATUS)
                .put("task_id",JSONObject.NULL).put("instruction_sha256",JSONObject.NULL).put("debug_nonce_sha256",JSONObject.NULL)
                 .put("expected_scope_sha256",JSONObject.NULL).put("actual_scope_sha256",JSONObject.NULL)
                .put("origin","user_recovery_confirmation").put("state","新会话空闲；旧任务中断，原清理状态未知")
                .put("pending",false).put("running",false).put("blocked",false).put("cleanup_known",true)
                .put("app_uid",a.uid).put("updated_wall_ms",a.wallMs).put("external_model",false)
                .put("automatic_resume",false).put("goal_independently_verified",false)
                .put("session_id",a.sessionId).put("recovery_transaction_id",a.transactionId)
                .put("recovery_prepare_sha256",a.prepareSha256).put("recovery_ack_sha256",a.ackSha256)
                .put("recovery_quiescence_sha256",a.quiescenceSha256)
                .put("old_native_cleanup","unknown").put("old_session_disposition","interrupted_not_resumed")
                .put("process_inventory_scope",RecoveryJournalTransaction.SCOPE);
    }
    private static JSONObject parseSessionJson(byte[] original)throws Exception{
        String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(original)).toString();
        JSONTokener parser=new JSONTokener(decoded);Object parsed=parser.nextValue();
        if(!(parsed instanceof JSONObject)||parser.nextClean()!=0)throw new IOException("session record must be one JSON object");
        return (JSONObject)parsed;
    }
    private static Map<String,Object> fieldsOf(JSONObject prior)throws Exception{
        Map<String,Object> fields=new LinkedHashMap<String,Object>();Iterator<String> names=prior.keys();
        while(names.hasNext()){String key=names.next();Object value=prior.get(key);fields.put(key,value==JSONObject.NULL?null:value);}
        return fields;
    }

    /** Inspect only: no old controller, instruction, nonce trigger or native process is resumed. */
    private void recoverPreviousSession() {
        SessionRecovery.Decision decision=SessionRecovery.unreadableRecord();
        File[] records=null;
        File latch=null;
        boolean latchPresent=false;
        boolean recoveryPending=false;
        byte[] original=null;
        JSONObject prior=null;
        Map<String,Object> fields=null;
        String readError=null;
        try{
            File files=context.getFilesDir().getCanonicalFile();
            File base=new File(files,"control-session.json");
            latch=new File(files,INTERRUPTION_LATCH);
            latchPresent=recordExists(latch);
            RecoveryJournalStore recoveryStore=new RecoveryJournalStore(context);
            recoveryPending=!recoveryStore.pendingBarriers().isEmpty();
            records=new File[]{base,new File(files,"control-session.json.bak"),new File(files,"control-session.json.new")};
            boolean present=recordExists(records[0]);
            boolean uncommitted=recordExists(records[1])|recordExists(records[2]);
            if(!present&&!uncommitted&&!latchPresent&&!recoveryPending)return;
            if(present){
                original=readSessionRecord(base);
                prior=parseSessionJson(original);fields=fieldsOf(prior);
                RecoveryJournalTransaction.Proof proof=null;
                if(RecoveryJournalTransaction.IDLE_STATUS.equals(fields.get("status"))&&!latchPresent&&!recoveryPending&&!uncommitted){
                    proof=RecoveryJournalTransaction.verifyReady(recoveryStore,android.os.Process.myUid(),
                            prior.getString("recovery_transaction_id"),original);
                }
                decision=SessionRecovery.evaluate(fields,android.os.Process.myUid(),false,proof);
                if(decision.allowNewTask&&proof!=null)acknowledgedSession=proof;
            }
            // Do not let AtomicFile silently discard an interrupted write and expose old "clean" state.
            if(uncommitted||recoveryPending)decision=SessionRecovery.unreadableRecord();
        }catch(Exception error){readError=error.getClass().getSimpleName();decision=SessionRecovery.unreadableRecord();}
        if(latchPresent)decision=SessionRecovery.evaluate(fields,android.os.Process.myUid(),true);
        taskId=decision.taskId;origin=decision.origin;instructionSha=decision.instructionSha256;nonceSha=decision.nonceSha256;
        pending=false;lastResult=null;
        if(decision.allowNewTask){
            state=acknowledgedSession==null?"上次任务已结束，退出状态已有记录；可开始新任务。"
                    :"新的空闲会话已核验，可开始新任务；旧任务仍为中断，原清理状态仍未知。";
            log=state+"\n没有自动恢复或重放上次任务。\n";
            return;
        }
        blocked=true;
        state="上次会话中断且退出状态未确认；应用重启后已暂停新任务，不会自动恢复或重做。";
        log=state+"\n";
        try{
            startupRecovery=new JSONObject().put("schema","hepta.session-recovery.v1")
                    .put("decision","blocked_interrupted").put("reason",decision.reason)
                    .put("previous_status",decision.priorStatus==null?JSONObject.NULL:decision.priorStatus)
                    .put("previous_session_sha256",original==null?JSONObject.NULL:HeptaAccessibilityService.sha(original))
                    .put("read_error",readError==null?JSONObject.NULL:readError)
                    .put("interruption_latch",INTERRUPTION_LATCH)
                    .put("interruption_latch_observed",latchPresent)
                    .put("recovery_pending_barrier_observed",recoveryPending)
                    .put("automatic_resume",false).put("native_cleanup_independently_observed",false);
            // Never parse away, replace or clear an existing latch, including an empty/malformed one.
            if(latchPresent||recoveryPending)return;
            if(records==null||latch==null)throw new IOException("prior session location unavailable");
            // Publish an independent durable barrier before AtomicFile may remove any old sidecar.
            createInterruptionLatch(latch,startupRecovery);
            startupRecovery.put("interruption_latch_observed",true).put("interruption_latch_synced",true);
            // A previously published interruption remains blocked without growing a new archive on every launch.
            if(decision.priorRecordValid&&"interrupted".equals(decision.priorStatus)){
                return;
            }
            startupRecovery.put("preserved_records",archivePriorRecords(records));
            persist("interrupted",false);
        }catch(Exception error){
            // Keep the original evidence unchanged when it cannot be preserved safely. Stay blocked in memory.
            log=log+"旧会话记录无法完整保存；仍保持阻塞，不会据此认定退出完成。\n";
        }
    }

    private static boolean recordExists(File file)throws Exception{
        try{android.system.Os.lstat(file.getPath());return true;}
        catch(android.system.ErrnoException error){if(error.errno==android.system.OsConstants.ENOENT)return false;throw error;}
    }

    /** Create once; never unlink a partial latch or mutate the old AtomicFile on failure. */
    private static void createInterruptionLatch(File latch,JSONObject reason)throws Exception{
        if(!latch.getCanonicalFile().equals(latch))throw new IOException("interruption latch path is not private");
        JSONObject value=new JSONObject().put("schema","hepta.session-interruption-latch.v1")
                .put("blocked",true).put("cleanup_known",false).put("automatic_resume",false)
                .put("app_uid",android.os.Process.myUid()).put("created_wall_ms",System.currentTimeMillis())
                .put("recovery_reason",reason);
        byte[] bytes=value.toString(2).getBytes(StandardCharsets.UTF_8);
        FileDescriptor out=android.system.Os.open(latch.getPath(),android.system.OsConstants.O_WRONLY
                |android.system.OsConstants.O_CREAT|android.system.OsConstants.O_EXCL
                |android.system.OsConstants.O_NOFOLLOW|android.system.OsConstants.O_CLOEXEC,0600);
        try{
            int offset=0;
            while(offset<bytes.length){int count=android.system.Os.write(out,bytes,offset,bytes.length-offset);
                if(count<=0)throw new IOException("interruption latch write was incomplete");offset+=count;}
            android.system.Os.fsync(out);
        }finally{android.system.Os.close(out);}
        FileDescriptor directory=android.system.Os.open(latch.getParentFile().getPath(),android.system.OsConstants.O_RDONLY
                |android.system.OsConstants.O_NOFOLLOW|android.system.OsConstants.O_CLOEXEC,0);
        try{
            android.system.StructStat parent=android.system.Os.fstat(directory);
            if(!android.system.OsConstants.S_ISDIR(parent.st_mode)||parent.st_uid!=android.os.Process.myUid())
                throw new IOException("interruption latch parent is not an owned directory");
            android.system.Os.fsync(directory);
        }finally{android.system.Os.close(directory);}
    }

    private static byte[] readSessionRecord(File file)throws Exception{
        if(!file.getCanonicalFile().equals(file))throw new IOException("session record is not a direct private file");
        android.system.StructStat stat=android.system.Os.lstat(file.getPath());
        if(!android.system.OsConstants.S_ISREG(stat.st_mode)||stat.st_uid!=android.os.Process.myUid()
                ||stat.st_nlink!=1||(stat.st_mode&0777)!=0600||stat.st_size<0||stat.st_size>SESSION_LIMIT)
            throw new IOException("session record ownership, type or size is invalid");
        try(FileInputStream in=new FileInputStream(file);ByteArrayOutputStream bytes=new ByteArrayOutputStream()){
            byte[] buffer=new byte[4096];int n;
            while((n=in.read(buffer))!=-1){if(bytes.size()+n>SESSION_LIMIT)throw new IOException("session record too large");bytes.write(buffer,0,n);}
            return bytes.toByteArray();
        }
    }

    private JSONArray archivePriorRecords(File[] records)throws Exception{
        File dir=new File(context.getFilesDir().getCanonicalFile(),"session-recovery");
        if(!dir.getCanonicalFile().equals(dir)||(!dir.isDirectory()&&!dir.mkdir()))throw new IOException("cannot preserve prior session");
        android.system.Os.chmod(dir.getPath(),0700);
        JSONArray archived=new JSONArray();
        for(File record:records){
            if(!recordExists(record))continue;
            byte[] bytes=readSessionRecord(record);
            String sha=HeptaAccessibilityService.sha(bytes);
            File target=new File(dir,record.getName()+"."+sha+".json");
            if(target.createNewFile()){
                android.system.Os.chmod(target.getPath(),0600);
                try(FileOutputStream out=new FileOutputStream(target)){out.write(bytes);out.getFD().sync();}
            }else if(!sha.equals(HeptaAccessibilityService.sha(readSessionRecord(target)))){
                throw new IOException("prior-session archive is incomplete or differs");
            }
            archived.put(new JSONObject().put("original_name",record.getName()).put("path",target.getPath())
                    .put("sha256",sha).put("bytes",bytes.length));
        }
        return archived;
    }

    private boolean persist(String status,boolean cleanupKnown) {
        if(taskId!=null&&controller!=null&&taskId.equals(controller.currentTaskId()))actualScopeSha=controller.currentActualScopeSha256();
        AtomicFile destination=new AtomicFile(new File(context.getFilesDir(),"control-session.json"));
        FileOutputStream out=null;
        try{
            JSONObject value=new JSONObject().put("schema","hepta.local-session.v1").put("status",status)
                .put("task_id",taskId==null?JSONObject.NULL:taskId).put("origin",origin==null?JSONObject.NULL:origin)
                .put("instruction_sha256",instructionSha==null?JSONObject.NULL:instructionSha)
                    .put("task_authorization_sha256",taskAuthorization==null?JSONObject.NULL:taskAuthorization.sha256)
                    .put("task_authorization",taskAuthorization==null?JSONObject.NULL:new JSONObject(taskAuthorization.evidence()))
                .put("debug_nonce_sha256",nonceSha==null?JSONObject.NULL:nonceSha)
                .put("expected_scope_sha256",QualificationScopeConfig.nullable(expectedScopeSha))
                .put("actual_scope_sha256",QualificationScopeConfig.nullable(actualScopeSha))
                .put("state",state).put("pending",pending).put("running",isRunning()).put("blocked",blocked)
                .put("cleanup_known",cleanupKnown).put("app_uid",android.os.Process.myUid()).put("updated_wall_ms",System.currentTimeMillis())
                .put("external_model",false).put("automatic_resume",false).put("goal_independently_verified",false);
            if(startupRecovery!=null)value.put("startup_recovery",startupRecovery);
            if(acknowledgedSession!=null){
                RecoveryJournalTransaction.Acknowledgement a=acknowledgedSession.acknowledgement;
                value.put("session_id",a.sessionId).put("recovery_transaction_id",a.transactionId)
                    .put("recovery_ack_sha256",a.ackSha256).put("old_native_cleanup","unknown")
                    .put("old_session_disposition","interrupted_not_resumed")
                    .put("process_inventory_scope",RecoveryJournalTransaction.SCOPE);
            }
            if(lastResult!=null)value.put("evidence_directory",lastResult.evidenceDirectory==null?JSONObject.NULL:lastResult.evidenceDirectory.getPath())
                .put("model_reported_success",lastResult.modelReportedSuccess).put("steps",lastResult.steps);
            out=destination.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));destination.finishWrite(out);out=null;
            android.system.Os.chmod(destination.getBaseFile().getPath(),0600);
            return true;
        }catch(Exception error){if(out!=null)destination.failWrite(out);blocked=true;state=state+"（会话记录保存失败，已暂停新任务）";publish();return false;}
    }
}
