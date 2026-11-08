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

/** Application lifetime session; the Accessibility service owns the controller itself. */
public final class LocalTaskSession {
    public interface Listener { void onSessionChanged(); }
    private final Context context;
    private final LocalModelEngine engine;
    private final Handler main = new Handler(Looper.getMainLooper());
    private WeakReference<Listener> ui = new WeakReference<>(null);
    private LocalTaskController controller;
    private HeptaAccessibilityService controllerService;
    private Runnable pendingStart;
    private String state = "输入任务，然后点击开始任务。", log = "", taskId, origin, instructionSha, nonceSha;
    private LocalTaskController.TaskResult lastResult;
    private boolean pending, blocked;
    private long generation;
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
    public String state() { return state; }
    public String log() { return log; }
    public String taskId() { return taskId; }
    public LocalTaskController.TaskResult lastResult() { return lastResult; }

    /** Caller first reserves this one session, then moves its Activity behind the target window. */
    public boolean schedule(final String owner, String source, String testNonceSha, long delayMillis) {
        if (Looper.myLooper()!=Looper.getMainLooper()) throw new IllegalStateException("schedule must run on main thread");
        if (isRunning() || engine.isBusy() || blocked) return false;
        final HeptaAccessibilityService service=HeptaAccessibilityService.connected();
        if (service==null) throw new IllegalStateException("请先启用 Hepta 本地操作无障碍服务");
        if (owner==null || owner.trim().isEmpty()) throw new IllegalArgumentException("请先输入要完成的手机任务");
        if (controllerService!=service) { controller=service.taskController(engine); controllerService=service; }
        final long epoch=++generation;
        origin=source; instructionSha=HeptaAccessibilityService.sha(owner.getBytes(StandardCharsets.UTF_8)); nonceSha=testNonceSha;
        taskId=null;lastResult=null;log="";pending=true;setState("任务已准备，正在等待前台画面稳定…");
        // A durable non-terminal reservation must precede any controller or model start.
        if(!persist("pending",true)){pending=false;blocked=true;publish();return false;}
        pendingStart=new Runnable(){public void run(){
            pendingStart=null;
            if(!pending)return;
            pending=false;
            if(HeptaAccessibilityService.connected()!=service){setState("无障碍服务已断开，任务未启动");persist("not_started",true);return;}
            try{
                boolean started=controller.start(owner,new LocalTaskController.Listener(){
                    public void onState(String value){if(epoch==generation&&!pending)receiveState(value);}
                    public void onFinished(LocalTaskController.TaskResult result){
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
        setState(result.summary);persist(result.status,result.cleanupKnown);
    }
    private void setState(String value) {
        state=value;log=log+value+"\n";
        if(log.length()>16000)log=log.substring(log.length()-16000);
        publish();
    }
    private void publish() { Listener listener=ui.get();if(listener!=null)listener.onSessionChanged(); }

    /** Inspect only: no old controller, instruction, nonce trigger or native process is resumed. */
    private void recoverPreviousSession() {
        SessionRecovery.Decision decision=SessionRecovery.unreadableRecord();
        File[] records=null;
        File latch=null;
        boolean latchPresent=false;
        byte[] original=null;
        JSONObject prior=null;
        Map<String,Object> fields=null;
        String readError=null;
        try{
            File files=context.getFilesDir().getCanonicalFile();
            File base=new File(files,"control-session.json");
            latch=new File(files,INTERRUPTION_LATCH);
            latchPresent=recordExists(latch);
            records=new File[]{base,new File(files,"control-session.json.bak"),new File(files,"control-session.json.new")};
            boolean present=recordExists(records[0]);
            boolean uncommitted=recordExists(records[1])|recordExists(records[2]);
            if(!present&&!uncommitted&&!latchPresent)return;
            if(present){
                original=readSessionRecord(base);
                String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(original)).toString();
                JSONTokener parser=new JSONTokener(decoded);
                Object parsed=parser.nextValue();
                if(!(parsed instanceof JSONObject)||parser.nextClean()!=0)throw new IOException("session record must be one JSON object");
                prior=(JSONObject)parsed;
                fields=new LinkedHashMap<String,Object>();
                Iterator<String> names=prior.keys();
                while(names.hasNext()){String key=names.next();Object value=prior.get(key);fields.put(key,value==JSONObject.NULL?null:value);}
                decision=SessionRecovery.evaluate(fields,android.os.Process.myUid());
            }
            // Do not let AtomicFile silently discard an interrupted write and expose old "clean" state.
            if(uncommitted)decision=SessionRecovery.unreadableRecord();
        }catch(Exception error){readError=error.getClass().getSimpleName();decision=SessionRecovery.unreadableRecord();}
        if(latchPresent)decision=SessionRecovery.evaluate(fields,android.os.Process.myUid(),true);
        taskId=decision.taskId;origin=decision.origin;instructionSha=decision.instructionSha256;nonceSha=decision.nonceSha256;
        pending=false;lastResult=null;
        if(decision.allowNewTask){
            state="上次任务已结束，退出状态已有记录；可开始新任务。";
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
                    .put("automatic_resume",false).put("native_cleanup_independently_observed",false);
            // Never parse away, replace or clear an existing latch, including an empty/malformed one.
            if(latchPresent)return;
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
                |android.system.OsConstants.O_DIRECTORY|android.system.OsConstants.O_CLOEXEC,0);
        try{android.system.Os.fsync(directory);}finally{android.system.Os.close(directory);}
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
        AtomicFile destination=new AtomicFile(new File(context.getFilesDir(),"control-session.json"));
        FileOutputStream out=null;
        try{
            JSONObject value=new JSONObject().put("schema","hepta.local-session.v1").put("status",status)
                .put("task_id",taskId==null?JSONObject.NULL:taskId).put("origin",origin==null?JSONObject.NULL:origin)
                .put("instruction_sha256",instructionSha==null?JSONObject.NULL:instructionSha)
                .put("debug_nonce_sha256",nonceSha==null?JSONObject.NULL:nonceSha)
                .put("state",state).put("pending",pending).put("running",isRunning()).put("blocked",blocked)
                .put("cleanup_known",cleanupKnown).put("app_uid",android.os.Process.myUid()).put("updated_wall_ms",System.currentTimeMillis())
                .put("external_model",false).put("automatic_resume",false).put("goal_independently_verified",false);
            if(startupRecovery!=null)value.put("startup_recovery",startupRecovery);
            if(lastResult!=null)value.put("evidence_directory",lastResult.evidenceDirectory==null?JSONObject.NULL:lastResult.evidenceDirectory.getPath())
                .put("model_reported_success",lastResult.modelReportedSuccess).put("steps",lastResult.steps);
            out=destination.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));destination.finishWrite(out);out=null;
            android.system.Os.chmod(destination.getBaseFile().getPath(),0600);
            return true;
        }catch(Exception error){if(out!=null)destination.failWrite(out);blocked=true;state=state+"（会话记录保存失败，已暂停新任务）";publish();return false;}
    }
}
