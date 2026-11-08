package org.trillionnium.hepta.localprobe;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;

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

    LocalTaskSession(Context context, LocalModelEngine engine) { this.context=context.getApplicationContext(); this.engine=engine; }
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
        persist("pending",true);
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
    private void persist(String status,boolean cleanupKnown) {
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
            if(lastResult!=null)value.put("evidence_directory",lastResult.evidenceDirectory==null?JSONObject.NULL:lastResult.evidenceDirectory.getPath())
                .put("model_reported_success",lastResult.modelReportedSuccess).put("steps",lastResult.steps);
            out=destination.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));destination.finishWrite(out);out=null;
            android.system.Os.chmod(destination.getBaseFile().getPath(),0600);
        }catch(Exception error){if(out!=null)destination.failWrite(out);state=state+"（会话记录保存失败）";publish();}
    }
}
