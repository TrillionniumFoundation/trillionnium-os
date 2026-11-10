package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.system.Os;
import org.json.JSONObject;
import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Application-owned permission preparation. No task, model, broker or display starts here. */
public final class BackgroundPermissionSession implements AutoCloseable {
    public interface Listener {void onPermissionPreparationChanged();}
    private final Context context;private final LocalModelEngine model;private final File files,journal,latch;
    private final ExecutorService worker;private final BackgroundPermissionPreparation.Launcher launcher;private final BackgroundPermissionPreparation.Clock clock;
    private final Handler main=new Handler(Looper.getMainLooper());
    private WeakReference<Listener> listener=new WeakReference<Listener>(null);
    private volatile LocalModelEngine.ExternalRunLease active;
    private volatile boolean blocked=true,closed;
    private volatile String state="后台执行权限尚未核验。每次核验只确认当时的权限，不保证永久授权。";
    private byte[] historicalUnknownRecord;
    BackgroundPermissionSession(Context context,LocalModelEngine model){
        this(context,model,()->new ProcessBuilder(BackgroundPermissionPreparation.command()).start(),SystemClock::elapsedRealtime,Executors.newSingleThreadExecutor());
    }
    /** Package-private IO seam; the ordinary Application always uses the fixed-command constructor. */
    BackgroundPermissionSession(Context context,LocalModelEngine model,BackgroundPermissionPreparation.Launcher launcher,BackgroundPermissionPreparation.Clock clock,ExecutorService worker){
        if(launcher==null||clock==null||worker==null)throw new IllegalArgumentException("owned preparation IO required");
        this.context=context.getApplicationContext();this.model=model;
        this.launcher=launcher;this.clock=clock;this.worker=worker;
        try{files=this.context.getFilesDir().getCanonicalFile();}catch(IOException error){throw new IllegalStateException("private app directory unavailable",error);}
        journal=new File(files,"background-permission-session.json");latch=new File(files,"background-permission-interrupted.json");recover();
    }
    public void bind(Listener value){listener=new WeakReference<Listener>(value);publish();}
    public void unbind(Listener value){if(listener.get()==value)listener.clear();}
    public boolean isRunning(){return active!=null;}
    public boolean isBlocked(){return blocked;}
    public boolean blocksOtherWork(){return blocked||isRunning();}
    public String state(){return state;}
    private static void requireMain(){if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("permission preparation requires the app main thread");}
    private void publish(){main.post(()->{Listener value=listener.get();if(value!=null)value.onPermissionPreparationChanged();});}
    private void setState(String value){state=value;publish();}
    public void cancelActive(){LocalModelEngine.ExternalRunLease lease=active;if(lease!=null)lease.cancel();}
    private BackgroundPermissionPreparation.Request request(String id){
        return new BackgroundPermissionPreparation.Request(id,context.getPackageName(),android.os.Process.myUid(),context.getApplicationInfo().uid,android.os.Process.myPid(),bootCount());
    }
    private int bootCount(){try{return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);}catch(Exception ignored){return -1;}}
    /** Called only by the visible MainActivity owner button, after Application-level idle checks. */
    void startFromOwnerButton(){
        requireMain();if(closed||blocksOtherWork()||model.isBusy())throw new IllegalStateException("权限准备或其他本地请求仍在运行，或退出未确认");
        final BackgroundPermissionPreparation.Request request=request(UUID.randomUUID().toString().replace("-",""));
        final LocalModelEngine.ExternalRunLease lease=model.reserveExternal(request.id);active=lease;
        setState("正在请求本机 root 授权，请在系统授权界面选择；最多等待 60 秒。尚未创建后台空间。");
        try{worker.execute(()->execute(request,lease));}
        catch(RuntimeException failure){
            // No worker was submitted, but release still requires an independently durable terminal.
            Map<String,Object> receipt=request.evidence(clock.elapsed());receipt.put("status","not_started");receipt.put("process_started",false);
            receipt.put("process_exit_observed",false);receipt.put("exit_code",null);receipt.put("cleanup_known",true);receipt.put("error",failure.toString());
            try{terminal(request,receipt,"result.json");lease.releaseAfterTerminalPublication(true);active=null;setState("权限准备未启动，请重新点击核验。");}
            catch(Exception publication){blocked=true;persistLatch(publication);setState("权限准备预约无法可靠保存；新请求已暂停。");}
            throw failure;
        }
    }
    private void execute(final BackgroundPermissionPreparation.Request request,final LocalModelEngine.ExternalRunLease lease){
        BackgroundPermissionPreparation.Result result=BackgroundPermissionPreparation.execute(request,
                new BackgroundPermissionPreparation.Lease(){public boolean cancelled(){return lease.isCancellationRequested();}public void attach(Process process){lease.attach(process);}},
                launcher,clock,
                new BackgroundPermissionPreparation.Journal(){
                    public void beforeLaunch(Map<String,Object> value)throws Exception{
                        ensureRun(request.id);Map<String,Object> pending=enrich(value,"pending");
                        if(historicalUnknownRecord!=null){MobiMindPrivateFiles.writeNew(new File(run(request.id),"previous-interrupted-record.json"),historicalUnknownRecord);pending.put("previous_interrupted_record_sha256",BackgroundPermissionPreparation.sha(historicalUnknownRecord));pending.put("previous_record_disposition","interrupted_not_resumed");}
                        MobiMindPrivateFiles.writeNew(new File(run(request.id),"request.json"),bytes(pending));replaceSession(pending);
                        historicalUnknownRecord=null;
                    }
                    public void terminal(Map<String,Object> value)throws Exception{BackgroundPermissionSession.this.terminal(request,value,"result.json");}
                });
        if(result.cleanupKnown){
            try{lease.releaseAfterTerminalPublication(true);active=null;
                setState(result.verified?"本次后台执行权限核验通过。尚未创建后台空间；授权期限由系统授权管理决定，不保证永久授权。":"本次权限未通过核验（"+result.status+"）。未创建后台空间，请查看记录后由你决定是否重新核验。");}
            catch(RuntimeException failure){blocked=true;persistLatch(failure);setState("权限准备的退出记录未能释放原进程占用；新请求已暂停。");}
        }else{
            blocked=true;
            if(!Boolean.TRUE.equals(result.receipt.get("terminal_receipt_published")))persistLatch(new IOException("permission terminal receipt unavailable"));
            setState("权限准备结果或进程退出尚未确认，未认定已授权。不会重试；等待这一个进程退出期间，新任务和诊断暂停。");
            if(result.process!=null&&Boolean.TRUE.equals(result.receipt.get("terminal_receipt_published")))watchOwnedExit(request,lease,result);
        }
        publish();
    }
    private static Map<String,Object> enrich(Map<String,Object> value,String phase){
        Map<String,Object> copy=new LinkedHashMap<String,Object>(value);copy.put("phase",phase);return copy;
    }
    private static byte[] bytes(Map<String,Object> value){return new JSONObject(value).toString().getBytes(StandardCharsets.UTF_8);}
    private File run(String id){return new File(new File(files,"background-permission-runs"),id);}
    private void ensureRun(String id)throws Exception{
        MobiMindPrivateFiles.directory(files,false);MobiMindPrivateFiles.directory(new File(files,"background-permission-runs"),false);
        MobiMindPrivateFiles.directory(run(id),false);MobiMindPrivateFiles.syncDirectory(new File(files,"background-permission-runs"));MobiMindPrivateFiles.syncDirectory(files);
    }
    private void noSidecars()throws Exception{
        if(MobiMindPrivateFiles.exists(new File(journal.getPath()+".bak"))||MobiMindPrivateFiles.exists(new File(journal.getPath()+".new"))
                ||MobiMindPrivateFiles.exists(latch))throw new IOException("permission preparation has an unresolved storage latch");
    }
    private synchronized void replaceSession(Map<String,Object> value)throws Exception{
        noSidecars();if(MobiMindPrivateFiles.exists(journal))MobiMindPrivateFiles.read(journal,65536,true);
        File temporary=new File(journal.getPath()+".new");MobiMindPrivateFiles.writeNew(temporary,bytes(value));
        Os.rename(temporary.getPath(),journal.getPath());MobiMindPrivateFiles.syncDirectory(files);
    }
    private void terminal(BackgroundPermissionPreparation.Request request,Map<String,Object> value,String name)throws Exception{
        ensureRun(request.id);Map<String,Object> terminal=enrich(value,"terminal");terminal.put("terminal_receipt_published",true);
        byte[] receipt=bytes(terminal);MobiMindPrivateFiles.writeNew(new File(run(request.id),name),receipt);
        terminal.put("result_sha256",BackgroundPermissionPreparation.sha(receipt));terminal.put("result_file",name);replaceSession(terminal);
    }
    private boolean terminalMatches(Map<String,Object> value)throws Exception{
        Object name=value.get("result_file");if(!(name instanceof String)||!((String)name).matches("(?:result|late-exit)\\.json"))return false;
        byte[] receipt=MobiMindPrivateFiles.read(new File(run((String)value.get("request_id")),(String)name),65536,true).bytes;
        if(!BackgroundPermissionPreparation.sha(receipt).equals(value.get("result_sha256")))return false;
        Map<String,Object> expected=new LinkedHashMap<String,Object>(value);expected.remove("result_sha256");expected.remove("result_file");
        return expected.equals(MobiMindContract.jsonObject(receipt));
    }
    private void recover(){
        try{
            noSidecars();if(!MobiMindPrivateFiles.exists(journal)){blocked=false;return;}
            byte[] raw=MobiMindPrivateFiles.read(journal,65536,true).bytes;Map<String,Object> value=MobiMindContract.jsonObject(raw);
            if(BackgroundPermissionPreparation.cleanTerminal(value,android.os.Process.myUid())&&terminalMatches(value)){
                blocked=false;state="已保留上次核验的结束记录；当前授权尚未核验，历史成功不代表当前或永久授权。";return;
            }
            if(!BackgroundPermissionPreparation.validReservation(value,android.os.Process.myUid())
                    ||!java.util.Arrays.asList("pending","terminal").contains(value.get("phase")))throw new IOException("malformed permission reservation");
            historicalUnknownRecord=raw;blocked=false;
            state="上次只读权限准备已中断，退出和授权结果未知；记录保留且不会恢复或重试。你可点击按钮发起一次新的独立核验。";
        }catch(Exception failure){blocked=true;persistLatch(failure);state="权限准备记录不完整或无法核验；未认定已授权，新请求已暂停。";}
    }
    /** Observe only this exact Process. A late exit never upgrades the authorization result. */
    private void watchOwnedExit(final BackgroundPermissionPreparation.Request request,final LocalModelEngine.ExternalRunLease lease,final BackgroundPermissionPreparation.Result prior){
        Thread watcher=new Thread(()->{
            try{
                int exit=prior.process.waitFor();
                Map<String,Object> late=new LinkedHashMap<String,Object>(prior.receipt);late.put("permission_verified",false);
                late.put("status","late_process_exit");late.put("process_exit_observed",true);late.put("exit_code",exit);late.put("cleanup_known",true);
                late.put("authorization_request_outcome_unknown",true);late.put("late_exit_observed",true);late.put("ended_elapsed_ms",clock.elapsed());
                late.put("prior_result_sha256",BackgroundPermissionPreparation.sha(MobiMindPrivateFiles.read(new File(run(request.id),"result.json"),65536,true).bytes));
                terminal(request,late,"late-exit.json");lease.releaseAfterTerminalPublication(true);active=null;blocked=false;
                setState("已观察到这次准备进程退出，授权结果仍未核验通过。未重试，也未创建后台空间；如需核验请再次点击按钮。");
            }catch(Exception failure){blocked=true;persistLatch(failure);setState("权限准备的迟到退出无法完整记录；未认定已授权，继续暂停新请求。");}
        },"hepta-permission-exit-observer");watcher.setDaemon(true);watcher.start();
    }
    private void persistLatch(Exception failure){
        try{if(!MobiMindPrivateFiles.exists(latch))MobiMindPrivateFiles.writeNew(latch,new JSONObject().put("schema","hepta.background-permission-interruption.v1")
                .put("blocked",true).put("permission_verified",false).put("automatic_resume",false).put("app_uid",android.os.Process.myUid())
                .put("reason",failure.getClass().getSimpleName()).toString().getBytes(StandardCharsets.UTF_8));}
        catch(Exception ignored){/* The independent in-memory barrier remains held. */}
    }
    @Override public void close(){closed=true;cancelActive();worker.shutdown();}
}
