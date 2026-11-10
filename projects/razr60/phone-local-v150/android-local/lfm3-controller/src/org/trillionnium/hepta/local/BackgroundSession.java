package org.trillionnium.hepta.local;

import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.net.Credentials;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.SystemClock;
import android.provider.Settings;
import android.system.Os;
import android.view.Display;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** One explicit owner-selected display lease. Never selects or falls back to display zero. */
final class BackgroundSession {
    static final String JOURNAL="background-session.active.json";
    static final String SCHEMA="hepta.background-session.v1";
    private static final String BROKER="org.trillionnium.hepta.background.BackgroundDisplayBroker";
    private static final int REQUEST_LIMIT=16384, RESPONSE_LIMIT=65536;
    private static final long TTL_MS=540000;
    /** No package is inferred from the model or from untrusted screen text. */
    static final class Selection {
        final String initialPackage;
        final List<String> allowedPackages;
        Selection(String initial,Set<String> allowed){
            if(allowed==null||allowed.isEmpty()||allowed.size()>6)throw new IllegalArgumentException("请选择 1 至 6 个后台任务应用");
            TreeSet<String> copy=new TreeSet<String>();
            for(String value:allowed){checkPackage(value);copy.add(value);}
            checkPackage(initial);
            if(!copy.contains(initial))throw new IllegalArgumentException("起始应用必须属于本次后台范围");
            initialPackage=initial;allowedPackages=Collections.unmodifiableList(new ArrayList<String>(copy));
        }
        JSONObject json()throws Exception{return new JSONObject().put("mode","background")
                .put("allowed_packages",new JSONArray(allowedPackages)).put("bootstrap_package",initialPackage)
                .put("bootstrap_source","owner_selected_initial_app").put("bootstrap_model_issued",false)
                .put("main_display_fallback",false).put("home_allowed",false);}
    }
    static final class Cleanup {
        final boolean known;final JSONObject evidence;
        Cleanup(boolean known,JSONObject evidence){this.known=known;this.evidence=evidence;}
    }
    final String taskId,generation,socketName,displayName,ownerSha256;
    final Selection selection;
    final long createdElapsed,expiresElapsed;
    private final Context context;
    private final QualificationScopeConfig.FilesRoot filesRoot;
    private final File journal;
    private final int bootCount;
    private volatile String state="INITIAL";
    private volatile int displayId=-1;
    private volatile boolean retired,spawnAttempted,bootstrapDispatched,cleanupConfirmed;
    private volatile JSONObject lastResponse;
    private Process brokerProcess;
    private volatile boolean brokerExitObserved;
    private volatile Integer brokerExitCode;
    private BrokerOutput brokerOutput;
    private Thread brokerOutputThread;

    BackgroundSession(Context context,String taskId,String owner,Selection selection,
                      QualificationScopeConfig.FilesRoot filesRoot)throws Exception{
        if(taskId==null||!taskId.matches("[0-9a-f]{32}")||selection==null)throw new IllegalArgumentException("后台会话身份缺失");
        this.context=context.getApplicationContext();this.taskId=taskId;this.selection=selection;this.filesRoot=filesRoot;
        filesRoot.unchanged(context);journal=new File(filesRoot.path,JOURNAL);
        if(MobiMindPrivateFiles.exists(journal))throw new IllegalStateException("上一次后台空间尚未确认释放，请先清理后台空间");
        generation=UUID.randomUUID().toString();socketName="hepta-bg-"+generation;displayName=socketName;
        ownerSha256=HeptaAccessibilityService.sha(owner.getBytes(StandardCharsets.UTF_8));
        createdElapsed=SystemClock.elapsedRealtime();expiresElapsed=createdElapsed+TTL_MS;bootCount=readBootCount(context);
    }
    boolean allows(String pkg){return selection.allowedPackages.contains(pkg);}
    int displayId(){return displayId;}
    boolean released(){return "RELEASED".equals(state)&&retired&&cleanupConfirmed;}
    synchronized void acceptReconciliation(JSONObject proof)throws Exception{
        if(!proof.getBoolean("cleanup_known")||!generation.equals(proof.optString("generation"))
                ||hasUnreleased(context)||!displayAbsent(context,displayId,displayName))
            throw new IOException("后台清理凭据不属于当前租约");
        retired=true;state="RELEASED";cleanupConfirmed=true;
    }
    synchronized JSONObject evidence(){
        try{return baseJournal().put("retired",retired).put("spawn_attempted",spawnAttempted)
                .put("bootstrap_dispatched",bootstrapDispatched).put("bootstrap_model_issued",false)
                .put("broker_process_exit_observed",brokerExitObserved)
                .put("broker_process_exit_code",brokerExitCode==null?JSONObject.NULL:brokerExitCode)
                .put("broker_output",brokerOutput==null?JSONObject.NULL:brokerOutput.evidence())
                .put("last_broker_response",lastResponse==null?JSONObject.NULL:new JSONObject(lastResponse.toString()));}
        catch(Exception failure){throw new IllegalStateException("后台会话凭据编码失败",failure);}
    }
    private JSONObject baseJournal()throws Exception{return new JSONObject().put("schema",SCHEMA).put("task_id",taskId)
            .put("app_uid",android.os.Process.myUid()).put("owner_sha256",ownerSha256)
            .put("generation",generation).put("socket",socketName).put("display_name",displayName)
            .put("display_id",displayId).put("state",state).put("created_elapsed_ms",createdElapsed).put("expires_elapsed_ms",expiresElapsed)
            .put("boot_count",bootCount).put("selection",selection.json());}

    /** Worker only. The durable lease precedes su and the first create request. */
    void start(HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())throw new IllegalStateException("后台创建不得阻塞主线程");
        requireUnlocked();filesRoot.unchanged(context);
        MobiMindPrivateFiles.writeNew(journal,baseJournal().toString().getBytes(StandardCharsets.UTF_8));
        if(cancellation.isCancelled())throw new IllegalStateException("任务已停止，后台空间未启动");
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.isFile()||!apk.isAbsolute())throw new IOException("已安装 APK 路径不可用");
        String packages=join(selection.allowedPackages);
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / "+BROKER
                +" --socket "+quote(socketName)+" --owner-uid "+android.os.Process.myUid()
                +" --generation "+quote(generation)+" --allowed-packages "+quote(packages)
                +" --ttl-ms "+TTL_MS+" --expires-elapsed-ms "+expiresElapsed;
        File taskRoot=MobiMindPrivateFiles.directory(new File(filesRoot.path,"control-tasks"),false);
        File taskDirectory=MobiMindPrivateFiles.directory(new File(taskRoot,taskId),false);
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        brokerProcess=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        spawnAttempted=true;
        brokerOutput=new BrokerOutput(brokerProcess,taskDirectory,taskId,generation,command);
        brokerOutputThread=new Thread(brokerOutput,"hepta-background-broker-output");
        brokerOutputThread.setDaemon(true);brokerOutputThread.start();
        long connectDeadline=Math.min(expiresElapsed,SystemClock.elapsedRealtime()+4500);
        Exception connectionFailure=null;
        while(SystemClock.elapsedRealtime()<connectDeadline){
            if(cancellation.isCancelled())throw new IllegalStateException("任务已停止，正在释放后台空间");
            try{JSONObject response=call("create",null,3000);accept(response,true);connectionFailure=null;break;}
            catch(ConnectionUnavailable error){connectionFailure=error;SystemClock.sleep(80);}
        }
        if(connectionFailure!=null||!"ACTIVE".equals(state))throw new IOException("手机后台执行服务未就绪；请确认本机已允许 Hepta 的 su 请求",connectionFailure);
        requireActive();saveJournal();
        if(cancellation.isCancelled())throw new IllegalStateException("任务已停止，正在释放后台空间");
        JSONObject launch=call("launch",selection.initialPackage,4000);bootstrapDispatched=launch.optBoolean("dispatched",false);
        accept(launch,true);requireActive();saveJournal();
    }
    /** No model-issued action can change the immutable package/display binding. */
    JSONObject action(String operation,String pkg,HeptaAccessibilityService.Cancellation cancellation)throws Exception{
        if(!"launch".equals(operation)&&!"back".equals(operation))throw new IllegalArgumentException("后台工具未授权");
        requireActive();if(cancellation.isCancelled())throw new IllegalStateException("任务已停止");
        if(pkg!=null&&!allows(pkg))throw new IllegalArgumentException("目标应用未在本次后台范围内");
        JSONObject response=call(operation,pkg,4000);accept(response,true);requireActive();return response;
    }
    void verifyRemote()throws Exception{requireActive();accept(call("state",null,1800),true);requireActive();}
    void requireActive(){
        if(retired||!"ACTIVE".equals(state)||displayId<=Display.DEFAULT_DISPLAY)
            throw new IllegalStateException("后台空间已退休或未完成创建；不会使用主屏幕");
        if(SystemClock.elapsedRealtime()>=expiresElapsed)throw new IllegalStateException("后台会话已到期");
        requireUnlocked();
        DisplayManager manager=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        Display display=manager==null?null:manager.getDisplay(displayId);
        if(display==null||!displayName.equals(display.getName())||!display.isValid())
            throw new IllegalStateException("后台屏幕身份已变化；不会使用主屏幕");
    }
    private void requireUnlocked(){KeyguardManager keyguard=(KeyguardManager)context.getSystemService(Context.KEYGUARD_SERVICE);
        if(keyguard==null||keyguard.isKeyguardLocked())throw new IllegalStateException("手机已锁定或锁屏状态未知，后台任务停止");}
    private synchronized void accept(JSONObject response,boolean requireSuccess)throws Exception{
        String next=response.getString("state");int id=response.getInt("display_id");
        if(displayId>0&&id!=displayId)throw new IOException("后台屏幕标识发生变化");
        if("ACTIVE".equals(next)&&id<=0)throw new IOException("后台服务返回了主屏或无效屏幕");
        state=next;if(id>0)displayId=id;lastResponse=new JSONObject(response.toString());
        if("RELEASED".equals(next)||"CLEANUP_UNKNOWN".equals(next)||"CLOSING".equals(next))retired=true;
        if(requireSuccess&&!response.getBoolean("ok"))throw new IOException("后台服务拒绝："+response.optString("error","operation_failed")
                +" "+response.optString("message",""));
    }
    private JSONObject call(String operation,String pkg,int budget)throws Exception{
        JSONObject request=new JSONObject().put("version",1).put("request_id",UUID.randomUUID().toString())
                .put("generation",generation).put("deadline_elapsed_ms",SystemClock.elapsedRealtime()+budget).put("op",operation);
        if(pkg!=null)request.put("package",pkg);
        return exchange(socketName,generation,request,budget+500);
    }
    private static final class ConnectionUnavailable extends IOException {
        private static final long serialVersionUID=1L;
        ConnectionUnavailable(IOException cause){super("后台 socket 尚不可连接",cause);}
    }
    /** One bounded framed request, peer UID checked before any request bytes are sent. */
    private static JSONObject exchange(String name,String generation,JSONObject request,int timeout)throws Exception{
        byte[] bytes=request.toString().getBytes(StandardCharsets.UTF_8);
        if(bytes.length<1||bytes.length>REQUEST_LIMIT)throw new IOException("后台请求长度越界");
        try(LocalSocket socket=new LocalSocket()){
            try{socket.connect(new LocalSocketAddress(name,LocalSocketAddress.Namespace.ABSTRACT));}
            catch(IOException unavailable){throw new ConnectionUnavailable(unavailable);}
            // Android creates the socket FD during connect; setSoTimeout before it throws.
            socket.setSoTimeout(timeout);
            Credentials peer=socket.getPeerCredentials();
            if(peer==null||(peer.getUid()!=0&&peer.getUid()!=2000))throw new IOException("后台服务身份不是 shell/root");
            DataOutputStream output=new DataOutputStream(socket.getOutputStream());output.writeInt(bytes.length);output.write(bytes);output.flush();
            DataInputStream input=new DataInputStream(socket.getInputStream());int length=input.readInt();
            if(length<1||length>RESPONSE_LIMIT)throw new IOException("后台响应长度越界");
            byte[] payload=new byte[length];input.readFully(payload);
            String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(payload)).toString();
            JSONTokener parser=new JSONTokener(decoded);Object value=parser.nextValue();
            if(!(value instanceof JSONObject)||parser.nextClean()!=0)throw new IOException("后台响应不是单个 JSON 对象");
            JSONObject result=(JSONObject)value;
            if(result.getInt("version")!=1||!request.getString("request_id").equals(result.getString("request_id"))
                    ||!generation.equals(result.getString("generation")))throw new IOException("后台响应请求/会话标识不匹配");
            String state=result.getString("state");
            if(!java.util.Arrays.asList("INITIAL","ACTIVE","CLOSING","RELEASED","CLEANUP_UNKNOWN").contains(state))throw new IOException("后台响应状态未知");
            result.getBoolean("ok");result.getInt("display_id");
            return result;
        }
    }
    private synchronized void saveJournal()throws Exception{
        filesRoot.unchanged(context);
        JSONObject old=readJournal(journal);
        if(!generation.equals(old.getString("generation")))throw new IOException("后台持久租约身份发生变化");
        File temporary=new File(filesRoot.path,JOURNAL+"."+UUID.randomUUID().toString()+".tmp");
        MobiMindPrivateFiles.writeNew(temporary,baseJournal().toString().getBytes(StandardCharsets.UTF_8));
        Os.rename(temporary.getPath(),journal.getPath());MobiMindPrivateFiles.syncDirectory(filesRoot.path);
    }
    /** Retire locally first; release proof requires broker readback and app-side display absence. */
    synchronized Cleanup close(){
        retired=true;boolean known=false;String error=null;
        try{
            if(!MobiMindPrivateFiles.exists(journal)){
                if(spawnAttempted)throw new IOException("后台持久租约消失，清理无法核验");
                state="RELEASED";known=true;
            }else if(!spawnAttempted){state="RELEASED";known=true;deleteJournal();}
            else if("RELEASED".equals(state)&&lastResponse!=null&&displayAbsent(context,displayId,displayName)){
                // A failed launch can already return system-confirmed RELEASED and exit the broker.
                known=true;deleteJournal();
            }
            else{
                JSONObject response=call("close",null,3500);accept(response,false);
                known=response.getBoolean("ok")&&"RELEASED".equals(state)&&displayAbsent(context,displayId,displayName);
                if(known)deleteJournal();else saveJournal();
            }
        }catch(Exception failure){known=false;error=HeptaAccessibilityService.message(failure);state="CLEANUP_UNKNOWN";
            try{if(MobiMindPrivateFiles.exists(journal))saveJournal();}catch(Exception ignored){} }
        if(brokerProcess!=null){
            try{brokerExitObserved=brokerProcess.waitFor(700,TimeUnit.MILLISECONDS);if(brokerExitObserved)brokerExitCode=brokerProcess.exitValue();}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            if(!known&&!brokerExitObserved)brokerProcess.destroy(); // Never counts as release evidence.
        }
        if(brokerOutput!=null){
            try{if(brokerOutputThread!=null)brokerOutputThread.join(200);}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            brokerOutput.persist("session_close_snapshot");
        }
        cleanupConfirmed=known;
        try{return new Cleanup(known,evidence().put("cleanup_known",known).put("cleanup_error",error==null?JSONObject.NULL:error));}
        catch(Exception impossible){throw new IllegalStateException(impossible);}
    }
    /** Diagnostic bytes only. A log, EOF, exit, or reported RELEASED never grants lease cleanup. */
    private static final class BrokerOutput implements Runnable {
        private static final int LIMIT=65536;
        private final Process process;
        private final File directory;
        private final String task,generation,commandSha,name;
        private final long started=SystemClock.elapsedRealtime();
        private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        private long count;
        private boolean eof,readFailed;
        private JSONObject captured;
        BrokerOutput(Process process,File directory,String task,String generation,String command){
            this.process=process;this.directory=directory;this.task=task;this.generation=generation;
            commandSha=HeptaAccessibilityService.sha(command.getBytes(StandardCharsets.UTF_8));
            name="background-broker-"+generation;
        }
        public void run(){
            try(InputStream input=process.getInputStream()){
                byte[] buffer=new byte[1024];int n;
                while((n=input.read(buffer))!=-1){synchronized(this){
                    count+=n;int keep=Math.min(n,LIMIT-bytes.size());
                    if(keep>0)bytes.write(buffer,0,keep);
                }}
                synchronized(this){eof=true;}
            }catch(IOException failure){synchronized(this){readFailed=true;}}
            finally{persist("stream_terminal");}
        }
        private JSONObject snapshot(byte[] kept)throws Exception{return new JSONObject()
                .put("schema","hepta.background-broker-output.v1").put("task_id",task).put("generation",generation)
                .put("app_uid",android.os.Process.myUid()).put("app_pid",android.os.Process.myPid())
                .put("process_binding","owned_java_process_merged_stream").put("process_reference",System.identityHashCode(process))
                .put("command_sha256",commandSha).put("started_elapsed_ms",started)
                .put("output_file",name+".bin").put("receipt_file",name+".json")
                .put("output_limit_bytes",LIMIT).put("observed_bytes",count).put("stored_bytes",kept.length)
                .put("stored_sha256",HeptaAccessibilityService.sha(kept)).put("overflow",count>LIMIT)
                .put("eof_seen",eof).put("read_failed",readFailed)
                .put("merged_stdout_stderr",true).put("model_input",false).put("release_evidence",false);}
        synchronized void persist(String reason){
            if(captured!=null)return;
            byte[] kept=bytes.toByteArray();JSONObject value;
            try{value=snapshot(kept).put("capture_reason",reason).put("persisted",false);}
            catch(Exception impossible){throw new IllegalStateException(impossible);}
            try{
                MobiMindPrivateFiles.directory(directory,false);
                MobiMindPrivateFiles.writeNew(new File(directory,name+".bin"),kept);
                value.put("persisted",true);
                MobiMindPrivateFiles.writeNew(new File(directory,name+".json"),value.toString().getBytes(StandardCharsets.UTF_8));
            }catch(Exception failure){
                try{value.put("persisted",false).put("persistence_error",failure.getClass().getSimpleName());}
                catch(Exception impossible){throw new IllegalStateException(impossible);}
            }
            captured=value;
        }
        synchronized JSONObject evidence()throws Exception{
            return captured==null?snapshot(bytes.toByteArray()).put("persisted",false):new JSONObject(captured.toString());
        }
    }
    private void deleteJournal()throws Exception{
        filesRoot.unchanged(context);JSONObject prior=readJournal(journal);
        if(!generation.equals(prior.getString("generation")))throw new IOException("后台租约已替换，不能删除");
        Os.remove(journal.getPath());MobiMindPrivateFiles.syncDirectory(filesRoot.path);
    }
    static boolean hasUnreleased(Context context){
        try{return MobiMindPrivateFiles.exists(new File(new QualificationScopeConfig.FilesRoot(context).path,JOURNAL));}
        catch(Exception unknown){return true;}
    }
    /** Recovery never restarts a task or creates a display. It can only close the recorded lease. */
    static Cleanup reconcile(Context context)throws Exception{
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);
        File path=new File(root.path,JOURNAL);
        if(!MobiMindPrivateFiles.exists(path))return new Cleanup(true,new JSONObject().put("cleanup_known",true).put("no_lease",true));
        JSONObject old=readJournal(path);String generation=old.getString("generation"),socket=old.getString("socket"),name=old.getString("display_name");
        if(!isUuid(generation)||!("hepta-bg-"+generation).equals(socket)||!socket.equals(name))throw new IOException("旧后台租约身份无效");
        int id=old.getInt("display_id");long expiry=old.getLong("expires_elapsed_ms");
        JSONObject response=null;boolean released=false;
        try{response=exchange(socket,generation,new JSONObject().put("version",1).put("request_id",UUID.randomUUID().toString())
                .put("generation",generation).put("deadline_elapsed_ms",SystemClock.elapsedRealtime()+3500).put("op","close"),4000);
            released=response.getBoolean("ok")&&"RELEASED".equals(response.getString("state"));
            if(response.getInt("display_id")>0)id=response.getInt("display_id");
        }catch(ConnectionUnavailable absent){/* Reconcile below only after expiry or a proved boot change. */}
        int currentBoot=readBootCount(context),oldBoot=old.getInt("boot_count");
        boolean newBoot=currentBoot>=0&&oldBoot>=0&&currentBoot!=oldBoot;
        boolean noLateCreate=newBoot||SystemClock.elapsedRealtime()>expiry+2000;
        boolean known=(released||noLateCreate)&&displayAbsent(context,id,name);
        JSONObject evidence=new JSONObject().put("schema","hepta.background-reconcile.v1").put("generation",generation)
                .put("cleanup_known",known).put("broker_released",released).put("boot_changed",newBoot)
                .put("no_late_create",noLateCreate).put("display_absence_observed",displayAbsent(context,id,name))
                .put("automatic_resume",false).put("broker_response",response==null?JSONObject.NULL:response);
        if(known){root.unchanged(context);if(!generation.equals(readJournal(path).getString("generation")))throw new IOException("清理期间后台租约发生变化");
            Os.remove(path.getPath());MobiMindPrivateFiles.syncDirectory(root.path);}
        return new Cleanup(known,evidence);
    }
    private static JSONObject readJournal(File file)throws Exception{
        byte[] bytes=MobiMindPrivateFiles.read(file,16384,true).bytes;
        JSONObject value=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
        if(!SCHEMA.equals(value.getString("schema"))||value.getInt("app_uid")!=android.os.Process.myUid())throw new IOException("后台租约格式或应用 UID 不匹配");
        long created=value.getLong("created_elapsed_ms"),expiry=value.getLong("expires_elapsed_ms");
        if(created<0||expiry<=created||expiry-created!=TTL_MS)throw new IOException("后台租约截止时间无效");
        return value;
    }
    private static boolean displayAbsent(Context context,int id,String name){
        DisplayManager manager=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        if(manager==null)return false;
        Display[] displays=manager.getDisplays();if(displays==null)return false;
        if(id>0&&manager.getDisplay(id)!=null)return false;
        for(Display display:displays)if(display==null||name.equals(display.getName()))return false;
        return true;
    }
    private static int readBootCount(Context context){try{return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT);}catch(Exception unknown){return -1;}}
    private static boolean isUuid(String value){return value!=null&&value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    private static void checkPackage(String value){if(value==null||value.length()>255||!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")
                ||"org.trillionnium.hepta.local".equals(value)||"com.android.systemui".equals(value)||"com.android.shell".equals(value))throw new IllegalArgumentException("后台应用包名无效或不允许");}
    private static String join(List<String> values){StringBuilder out=new StringBuilder();for(String value:values){if(out.length()>0)out.append(',');out.append(value);}return out.toString();}
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
