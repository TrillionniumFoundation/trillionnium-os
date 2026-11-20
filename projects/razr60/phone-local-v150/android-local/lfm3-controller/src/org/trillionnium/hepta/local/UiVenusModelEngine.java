package org.trillionnium.hepta.local;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.system.Os;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Application-owned, one-shot visual inference only. Never implements LocalInference or dispatches tools. */
public final class UiVenusModelEngine implements AutoCloseable {
    public static final long MIN_AVAILABLE_BYTES=UiVenusPins.MIN_AVAILABLE_BYTES;
    static final long PREFLIGHT_LIMIT_MS=30000L, SUPERVISOR_LIMIT_MS=325000L;
    private static final String PACKAGE="org.trillionnium.hepta.local";
    private final Context context;
    private final File files,journal,latch;
    private final LocalModelEngine broker;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile LocalModelEngine.ExternalRunLease active;
    private volatile boolean blocked,closed;
    private volatile String recoveryMessage="";
    private volatile Result lastResult;

    UiVenusModelEngine(Context context,LocalModelEngine broker){
        this.context=context.getApplicationContext();this.broker=broker;
        try{files=this.context.getFilesDir().getCanonicalFile();}
        catch(IOException failure){throw new IllegalStateException("private app root unavailable",failure);}
        journal=new File(files,"ui-venus-probe-session.json");latch=new File(files,"ui-venus-probe-interrupted.json");
        recover();
    }
    public interface Listener {void onFinished(Result result);}
    public static final class Result {
        public final String runId,status,rawText;public final Integer exitCode;
        public final boolean processExitObserved,inferenceCompleted,cleanupKnown;
        public final File runDirectory;public final JSONObject receipt;
        Result(String id,String status,String raw,Integer exit,boolean observed,boolean complete,boolean cleanup,File directory,JSONObject receipt){
            runId=id;this.status=status;rawText=raw;exitCode=exit;processExitObserved=observed;inferenceCompleted=complete;
            cleanupKnown=cleanup;runDirectory=directory;this.receipt=receipt;
        }
    }
    public boolean isBusy(){return active!=null;}
    public boolean isBlocked(){return blocked;}
    public String recoveryMessage(){return recoveryMessage;}
    public Result lastResult(){return lastResult;}
    public void cancelActive(){LocalModelEngine.ExternalRunLease lease=active;if(lease!=null)lease.cancel();}

    void start(PrivateUiVenusProbe request,LocalTaskSession tasks,Listener listener)throws Exception{
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("diagnostic starts on the app main thread");
        if(request==null||tasks==null||listener==null||closed||blocked||active!=null||broker.isBusy()||tasks.isRunning()||tasks.isBlocked())
            throw new IllegalStateException("another task/diagnostic is active or cleanup is unknown");
        LocalModelEngine.ExternalRunLease lease=broker.reserveExternal(request.id);active=lease;
        try{
            publishSession(request,"pending",true,false,false,false,null,false,false);
            worker.execute(() -> execute(request,lease,listener));
        }catch(Exception failure){
            // Keep the shared slot closed if the durable reservation cannot be resolved.
            try{publishSession(request,"submission_failed",false,false,false,false,null,true,false);
                lease.releaseAfterTerminalPublication(true);active=null;}
            catch(Exception publication){blocked=true;recoveryMessage="视觉诊断预约状态无法可靠保存；已暂停新本地请求。";persistInterruption(publication);}
            throw failure;
        }
    }
    private void execute(PrivateUiVenusProbe request,LocalModelEngine.ExternalRunLease lease,Listener listener){
        long started=SystemClock.elapsedRealtime();File run=new File(new File(files,"ui-venus-runs"),request.id);
        Map<String,Object> app=new LinkedHashMap<String,Object>();List<String> validation=new ArrayList<String>();
        Map<String,Object> core=new LinkedHashMap<String,Object>(),processBinding=new LinkedHashMap<String,Object>();
        Map<String,byte[]> artifacts=new LinkedHashMap<String,byte[]>();
        byte[] raw=new byte[0];String rawText="",status="preflight_failed",error=null;
        Process process=null;Integer exit=null;boolean observed=false,complete=false,timedOut=false,forced=false,logLimit=false,terminated=false;
        try{
            MobiMindPrivateFiles.directory(files,false);MobiMindPrivateFiles.directory(new File(files,"ui-venus-runs"),false);
            MobiMindPrivateFiles.directory(run,true);
            UiVenusInputContract.Inputs in=request.inputs;
            app.put("schema","hepta.ui-venus.app-model-only.v1");app.put("request_id",request.id);app.put("nonce_sha256",request.nonceSha);
            app.put("owner_sha256",in.ownerSha);app.put("fixture_sha256",in.fixtureSha);app.put("prompt_sha256",in.promptSha);
            app.put("system_sha256",in.systemSha);app.put("image_sha256",in.imageSha);app.put("official_system_template_sha256",UiVenusPins.OFFICIAL_SYSTEM_SHA);
            app.put("model_repository",UiVenusPins.MODEL_REPO);app.put("model_revision",UiVenusPins.MODEL_REVISION);
            app.put("sdk_source_commit",UiVenusPins.SDK_COMMIT);app.put("llama_source_commit",UiVenusPins.LLAMA_COMMIT);
            app.put("app_uid",android.os.Process.myUid());app.put("app_pid",android.os.Process.myPid());app.put("package_name",context.getPackageName());
            app.put("expected_parent_pid",android.os.Process.myPid());app.put("parent_death_guard_requested",true);
            app.put("actions_executed",false);app.put("external_model_used",false);app.put("automatic_retry",false);app.put("automatic_resume",false);
            app.put("raw_output_is_not_dispatched",true);app.put("screenshot_live_freshness_claimed",false);app.put("ordinary_app_qualification_claimed",false);
            app.put("full_multimodal_input_qualified",false);app.put("no_context_shift_proven",false);app.put("per_operator_backend_coverage_proven",false);
            app.put("history_policy","initial_frame_empty_history");app.put("historical_turns",0);app.put("image_resize_by_app",false);
            app.put("requested_compute","npu");app.put("requested_vision_device","GPUOpenCL");app.put("context_tokens",UiVenusPins.CONTEXT);
            app.put("max_tokens",UiVenusPins.MAX_TOKENS);app.put("native_deadline_ms",UiVenusPins.DEADLINE_MS);
            app.put("preflight_limit_ms",PREFLIGHT_LIMIT_MS);app.put("process_supervisor_limit_ms",SUPERVISOR_LIMIT_MS);
            app.put("supervisor_origin","elapsedRealtime at successful ProcessBuilder.start; preflight separately bounded");
            if(!PACKAGE.equals(context.getPackageName())||!android.os.Process.isApplicationUid(android.os.Process.myUid()))throw new IOException("ordinary Hepta application UID required");
            PackageInfo info=context.getPackageManager().getPackageInfo(context.getPackageName(),PackageManager.GET_PERMISSIONS);
            if(info.requestedPermissions!=null)for(String permission:info.requestedPermissions)if("android.permission.INTERNET".equals(permission))throw new IOException("VLM diagnostic requires an APK without INTERNET permission");
            app.put("internet_permission_declared",false);
            if(!UiVenusPins.workerQualified())throw new IOException("independent UI-Venus App worker build pin is not qualified");
            ActivityManager.MemoryInfo memory=new ActivityManager.MemoryInfo();
            ((ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE)).getMemoryInfo(memory);
            MemoryAvailability available=MemoryAvailability.read(memory.availMem,memory.totalMem,memory.lowMemory);
            app.put("available_memory_bytes",available.availableBytes);app.put("available_memory_source",available.source);
            app.put("minimum_available_memory_bytes",MIN_AVAILABLE_BYTES);app.put("memory_threshold_is_not_peak_memory_proof",true);
            if(!available.admits(MIN_AVAILABLE_BYTES))throw new IOException("available physical RAM below the explicit 8GiB engineering admission");
            cancelled(lease);
            File model=new File(files,UiVenusPins.MODEL_DIRECTORY);
            if(!model.equals(model.getCanonicalFile()))throw new IOException("model directory aliases");
            MobiMindPrivateFiles.directory(model,false);
            // Java does not map or duplicate the 6.8GB weights. The pinned core hashes both complete files through held FDs.
            for(UiVenusPins.FilePin pin:UiVenusPins.models()){
                File path=new File(model,pin.name);android.system.StructStat st=Os.lstat(path.getPath());
                if(!path.equals(path.getCanonicalFile())||!android.system.OsConstants.S_ISREG(st.st_mode)||st.st_uid!=android.os.Process.myUid()
                        ||st.st_nlink!=1||(st.st_mode&0777)!=0600||st.st_size!=pin.bytes)throw new IOException("complete private model metadata mismatch: "+pin.name);
            }
            File nativeDir=new File(context.getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            if(!nativeDir.getPath().startsWith("/data/app/"))throw new IOException("installed APK native directory required");
            File runner=runtime(nativeDir,UiVenusPins.WORKER,UiVenusPins.WORKER_BYTES,UiVenusPins.WORKER_SHA,lease);
            for(UiVenusPins.FilePin pin:UiVenusPins.sdk())runtime(nativeDir,pin.name,pin.bytes,pin.sha256,lease);
            if(!runner.canExecute())throw new IOException("installed UI-Venus PIE is not executable");
            app.put("runner_path",runner.getPath());app.put("worker_sha256",UiVenusPins.WORKER_SHA);
            app.put("model_directory",model.getPath());app.put("runtime_directory",nativeDir.getPath());
            MobiMindPrivateFiles.writeNew(new File(run,"prompt.txt"),in.prompt());MobiMindPrivateFiles.writeNew(new File(run,"system.txt"),in.system());
            MobiMindPrivateFiles.writeNew(new File(run,"screen.png"),in.image());MobiMindPrivateFiles.writeNew(new File(run,"FIXTURE.json"),in.fixture());
            MobiMindPrivateFiles.writeNew(new File(run,"owner.txt"),in.owner.getBytes(StandardCharsets.UTF_8));
            File stdout=new File(run,"stdout.log"),stderr=new File(run,"stderr.log");
            MobiMindPrivateFiles.writeNew(stdout,new byte[0]);MobiMindPrivateFiles.writeNew(stderr,new byte[0]);
            List<String> argv=Arrays.asList(runner.getPath(),"--expected-parent-pid",Integer.toString(android.os.Process.myPid()),
                "--expected-app-uid",Integer.toString(android.os.Process.myUid()),"--app-files-dir",files.getPath(),
                "--request-id",request.id,"--mode","vlm","--runtime","llama_cpp","--compute","npu","--vit-device","GPUOpenCL",
                "--model",new File(model,UiVenusPins.models()[0].name).getPath(),"--mmproj",new File(model,UiVenusPins.models()[1].name).getPath(),
                "--prompt-file",new File(run,"prompt.txt").getPath(),"--system-file",new File(run,"system.txt").getPath(),"--image",new File(run,"screen.png").getPath(),
                "--result-file",new File(run,"native-result.json").getPath(),"--text-file",new File(run,"raw.txt").getPath(),
                "--ctx-size","8192","--max-tokens","1024","--threads","4","--timeout-ms","300000","--log-level","debug");
            app.put("argv",argv);app.put("prompt_wrapped_by_app",false);
            cancelled(lease);long preflight=SystemClock.elapsedRealtime()-started;app.put("preflight_elapsed_ms",preflight);
            if(preflight>PREFLIGHT_LIMIT_MS)throw new IOException("bounded Java preflight deadline exhausted before native launch");
            publishSession(request,"launching",false,true,false,false,null,false,false);
            ProcessBuilder builder=new ProcessBuilder(argv);builder.directory(run);builder.redirectOutput(stdout);builder.redirectError(stderr);
            Map<String,String> env=builder.environment();
            env.put("LD_LIBRARY_PATH",nativeDir.getPath()+":/vendor/lib64");
            env.put("ADSP_LIBRARY_PATH",nativeDir.getPath()+";/vendor/lib/rfsa/adsp;/system/lib/rfsa/adsp;/dsp");
            env.put("HEPTA_LOCAL_NATIVE_LIB_DIR",nativeDir.getPath());env.put("GENIEX_PLUGIN_PATH",nativeDir.getPath());
            env.put("TMPDIR",run.getPath());env.remove("LD_PRELOAD");env.remove("LD_AUDIT");env.remove("GENIEX_QAIRT_LIB");
            app.put("configured_ld_library_path",env.get("LD_LIBRARY_PATH"));app.put("configured_adsp_library_path",env.get("ADSP_LIBRARY_PATH"));
            app.put("configured_linker_environment_is_not_runtime_maps_proof",true);
            process=builder.start();long launched=SystemClock.elapsedRealtime();lease.attach(process);long terminationAt=0;
            publishSession(request,"running",false,true,true,false,null,false,false);
            while(true){
                if(process.waitFor(100,TimeUnit.MILLISECONDS)){exit=process.exitValue();observed=true;break;}
                long now=SystemClock.elapsedRealtime();
                if(now-launched>=SUPERVISOR_LIMIT_MS)timedOut=true;
                if(stdout.length()>8*1024*1024||stderr.length()>8*1024*1024)logLimit=true;
                if(lease.isCancellationRequested()||timedOut||logLimit){
                    if(terminationAt==0){terminationAt=now;process.destroy();terminated=true;}
                    if(!forced&&now-terminationAt>=2000){process.destroyForcibly();forced=true;}
                    if(now-terminationAt>=12000)break;
                }
            }
            app.put("process_supervised_elapsed_ms",SystemClock.elapsedRealtime()-launched);
            // A fast exit may precede the next live polling iteration; it cannot bypass the log cap.
            if(stdout.length()>8*1024*1024||stderr.length()>8*1024*1024)logLimit=true;
            if(exit!=null&&exit==124)timedOut=true;
            core=readObject(new File(run,"native-result.json"),validation);processBinding=readObject(new File(run,"app-process-binding.json"),validation);
            if(Boolean.TRUE.equals(core.get("deadline_observed")))timedOut=true;
            for(String name:new String[]{"raw.txt","formatted-prompt.txt","gguf-chat-template.jinja","diagnostic-text-only-token-ids.le32","sdk-generation-prefix.txt"}){
                try{artifacts.put(name,MobiMindPrivateFiles.read(new File(run,name),1048576,true).bytes);}
                catch(Exception invalid){validation.add(name+": "+invalid.getClass().getSimpleName());}
            }
            if(artifacts.get("raw.txt")!=null)raw=artifacts.get("raw.txt");
            try{rawText=MobiMindContract.utf8(raw);}catch(Exception invalid){validation.add("raw_utf8");}
            UiVenusContract.Expected expected=new UiVenusContract.Expected(request.id,android.os.Process.myUid(),android.os.Process.myPid(),files.getPath(),nativeDir.getPath(),in);
            validation.addAll(UiVenusContract.verifyCore(core,artifacts,expected,exit==null?-1:exit));
            validation.addAll(UiVenusProcessContract.verify(processBinding,core,expected,exit==null?-1:exit));
            complete=observed&&exit!=null&&exit==0&&validation.isEmpty()&&!lease.isCancellationRequested()&&!timedOut&&!logLimit;
            status=!observed?"cleanup_unknown":complete?"completed":timedOut?"timed_out":lease.isCancellationRequested()
                ?(exit!=null&&exit!=0&&(terminated||"cancelled".equals(core.get("worker_outcome")))?"cancelled":"cancel_race"):"native_failed";
        }catch(Exception failure){
            error=failure.getClass().getSimpleName()+": "+String.valueOf(failure.getMessage());complete=false;
            if(process!=null&&process.isAlive()){
                process.destroy();terminated=true;
                try{if(!process.waitFor(2000,TimeUnit.MILLISECONDS)){process.destroyForcibly();forced=true;}
                    if(process.waitFor(10000,TimeUnit.MILLISECONDS)){observed=true;exit=process.exitValue();}}
                catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            }
            if(process!=null&&!process.isAlive()){observed=true;exit=process.exitValue();}
            status=process==null?(lease.isCancellationRequested()?"cancelled_before_start":"preflight_failed")
                :!observed?"cleanup_unknown":lease.isCancellationRequested()?(exit!=null&&exit!=0?"cancelled":"cancel_race"):"native_failed";
        }finally{
            boolean cleanupKnown=process==null||observed;
            app.put("status",status);app.put("error",error);app.put("process_started",process!=null);app.put("process_exit_observed",observed);
            app.put("exit_code",exit);app.put("inference_completed",complete);app.put("native_binding_valid",validation.isEmpty()&&complete);
            app.put("native_binding_errors",validation);app.put("native_receipt",core);app.put("native_app_process_binding",processBinding);
            app.put("cancel_requested",lease.isCancellationRequested());app.put("timeout_observed",timedOut);app.put("log_limit_observed",logLimit);
            app.put("termination_sent",terminated);app.put("force_destroy_sent",forced);app.put("raw_bytes_read",raw.length);app.put("raw_sha256_read",MobiMindContract.sha(raw));
            app.put("elapsed_ms",SystemClock.elapsedRealtime()-started);app.put("cleanup_known",cleanupKnown);
            JSONObject resultJson=new JSONObject(app);
            try{
                if(!run.isDirectory())throw new IOException("diagnostic evidence directory was never reserved");
                MobiMindPrivateFiles.writeNew(new File(run,"app-receipt.json"),resultJson.toString(2).getBytes(StandardCharsets.UTF_8));
                publishSession(request,status,false,false,process!=null,observed,exit,cleanupKnown,complete);
                if(cleanupKnown){lease.releaseAfterTerminalPublication(true);active=null;}
            }catch(Exception publication){
                cleanupKnown=false;complete=false;status="cleanup_unknown";blocked=true;
                recoveryMessage="UI-Venus诊断退出或回执保存状态不明；新本地请求已暂停，不会执行模型输出。";
                persistInterruption(publication);
                try{resultJson.put("terminal_publication_error",publication.toString()).put("cleanup_known",false).put("inference_completed",false);}
                catch(Exception ignored){/* Shared lease remains retained. */}
            }
            if(!cleanupKnown){blocked=true;recoveryMessage="UI-Venus诊断退出状态尚未确认；新本地请求已暂停。";}
            lastResult=new Result(request.id,status,rawText,exit,observed,complete,cleanupKnown,run,resultJson);
            final Result delivered=lastResult;main.post(() -> {try{listener.onFinished(delivered);}catch(RuntimeException ignored){/* UI cannot release ownership. */}});
        }
    }
    private File runtime(File directory,String name,long bytes,String sha,LocalModelEngine.ExternalRunLease lease)throws Exception{
        cancelled(lease);File path=new File(directory,name);
        MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,(int)bytes,false);
        if(read.bytes.length!=bytes||!sha.equals(MobiMindContract.sha(read.bytes)))throw new IOException("installed runtime pin mismatch: "+name);
        return path;
    }
    private static void cancelled(LocalModelEngine.ExternalRunLease lease)throws IOException{if(lease.isCancellationRequested())throw new IOException("diagnostic cancelled before native launch");}
    private static Map<String,Object> readObject(File path,List<String> errors){
        try{return MobiMindContract.jsonObject(MobiMindPrivateFiles.read(path,1048576,true).bytes);}
        catch(Exception failure){errors.add(path.getName()+": "+failure.getClass().getSimpleName());return Collections.emptyMap();}
    }
    private void publishSession(PrivateUiVenusProbe request,String status,boolean pending,boolean running,boolean processStarted,
                                boolean exitObserved,Integer exit,boolean cleanup,boolean binding)throws Exception{
        if(MobiMindPrivateFiles.exists(new File(journal.getPath()+".bak"))||MobiMindPrivateFiles.exists(new File(journal.getPath()+".new"))
                ||MobiMindPrivateFiles.exists(latch))throw new IOException("diagnostic session has an interruption barrier");
        if(MobiMindPrivateFiles.exists(journal))MobiMindPrivateFiles.read(journal,65536,true);
        JSONObject value=new JSONObject().put("schema","hepta.ui-venus.diagnostic-session.v1").put("request_id",request.id)
                .put("nonce_sha256",request.nonceSha).put("owner_sha256",request.inputs.ownerSha).put("app_uid",android.os.Process.myUid())
                .put("status",status).put("pending",pending).put("running",running).put("process_started",processStarted)
                .put("process_exit_observed",exitObserved).put("exit_code",exit==null?JSONObject.NULL:exit).put("cleanup_known",cleanup)
                .put("native_binding_valid",binding).put("actions_executed",false).put("external_model_used",false).put("automatic_resume",false)
                .put("updated_wall_ms",System.currentTimeMillis());
        AtomicFile file=new AtomicFile(journal);FileOutputStream out=null;
        try{out=file.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));out.getFD().sync();file.finishWrite(out);out=null;Os.chmod(journal.getPath(),0600);MobiMindPrivateFiles.syncDirectory(files);}
        finally{if(out!=null)file.failWrite(out);}
    }
    private void recover(){
        try{
            boolean exists=MobiMindPrivateFiles.exists(journal),side=MobiMindPrivateFiles.exists(new File(journal.getPath()+".bak"))
                    |MobiMindPrivateFiles.exists(new File(journal.getPath()+".new")),latched=MobiMindPrivateFiles.exists(latch);
            if(!exists&&!side&&!latched)return;
            if(exists&&!side&&!latched&&UiVenusSessionContract.clean(MobiMindContract.jsonObject(MobiMindPrivateFiles.read(journal,65536,true).bytes),android.os.Process.myUid()))return;
            throw new IOException("previous visual diagnostic has no committed clean terminal receipt");
        }catch(Exception failure){
            blocked=true;recoveryMessage="上次视觉诊断中断且退出未确认；不会自动恢复或重放，新本地请求已暂停。";
            // Application inspects all three journals before reserving one shared recovery barrier.
            persistInterruption(failure);
        }
    }
    private void persistInterruption(Exception failure){
        try{if(!MobiMindPrivateFiles.exists(latch))MobiMindPrivateFiles.writeNew(latch,
                new JSONObject().put("schema","hepta.ui-venus.interruption-latch.v1").put("blocked",true)
                .put("cleanup_known",false).put("automatic_resume",false).put("app_uid",android.os.Process.myUid())
                .put("reason",failure.getClass().getSimpleName()).toString(2).getBytes(StandardCharsets.UTF_8));}
        catch(Exception ignored){/* Keep the shared reservation; a storage error is never proof of clean exit. */}
    }
    @Override public void close(){closed=true;cancelActive();worker.shutdown();}
}
