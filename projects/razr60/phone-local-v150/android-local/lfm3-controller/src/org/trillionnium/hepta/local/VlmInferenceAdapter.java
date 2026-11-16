package org.trillionnium.hepta.local;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Current-frame local inference with one process per request and one slot per task.
 * Raw text remains model output: only the existing controller may parse or dispatch it.
 */
public final class VlmInferenceAdapter implements LocalInference {
    private static final String PACKAGE="org.trillionnium.hepta.local";
    private static final String TASK_SCHEMA="hepta.vlm.task-aggregate.v1";
    private static final long MIN_AVAILABLE_BYTES=6L<<30;
    private static final long MAX_REQUEST_MILLIS=120000L;
    private static final int MAX_ROUNDS=64,RECEIPT_LIMIT=2*1024*1024,LOG_LIMIT=8*1024*1024;
    private final Context context;
    private final LocalModelEngine engine;
    private final LocalRuntimeConfig configuration;
    private final File files;
    private volatile Task task;
    private volatile TaskCleanup lastCleanup;

    public VlmInferenceAdapter(Context context,LocalModelEngine engine) {
        if(context==null||engine==null)throw new IllegalArgumentException("context and shared engine required");
        this.context=context.getApplicationContext();this.engine=engine;
        configuration=engine.configuration();
        if(configuration.profile!=ModelProfile.GUI_OWL_4B||!"npu".equals(configuration.compute)
                ||configuration.contextTokens!=8192||configuration.threads!=4)
            throw new IllegalArgumentException("the pinned GUI-Owl HTP0/GPUOpenCL configuration is required");
        try{files=this.context.getFilesDir().getCanonicalFile();}
        catch(IOException failure){throw new IllegalStateException("private app root unavailable",failure);}
    }
    @Override public LocalRuntimeConfig configuration(){return configuration;}
    @Override public boolean acceptsObservedImage(){return true;}
    @Override public boolean modelOutputDispatchAllowed(){return !configuration.visualObservationOnly;}
    @Override public long requestCompletionGraceMillis(){return VlmPins.COMPLETION_GRACE_MILLIS;}

    private static String id(){return UUID.randomUUID().toString().replace("-","");}
    private final class Task {
        final LocalModelEngine.TaskExternalLease lease;
        final String taskId,generation;
        final File directory;
        final List<Round> rounds=new ArrayList<>();
        volatile Round current;
        volatile boolean failed,ending,publicationFailed,finishExpired;
        boolean pendingPublished;
        Stamp pendingReceipt;
        String ownerSha256,backgroundGeneration;
        Integer displayId;
        Future<?> finisher;
        long finishSubmitted,finishDeadline;
        volatile TaskCleanup cleanup;
        Task(LocalModelEngine.TaskExternalLease lease){
            this.lease=lease;taskId=lease.taskId;generation=lease.generation();
            directory=new File(new File(files,"runs"),generation);
        }
    }
    private static final class Stamp {
        final File path;final int limit;final long bytes;final String sha256;
        Stamp(File path,int limit,byte[] contents){
            this.path=path;this.limit=limit;bytes=contents.length;sha256=MobiMindContract.sha(contents);
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<>();out.put("path",path.getPath());
            out.put("bytes",bytes);out.put("sha256",sha256);return out;
        }
        void verify()throws Exception{
            MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,limit,true);
            need(read.bytes.length==bytes&&sha256.equals(MobiMindContract.sha(read.bytes)),"private evidence changed");
            read.unchangedPath();
        }
    }
    private static final class FileIdentity {
        final File path;final StructStat stat;
        FileIdentity(File path,StructStat stat){this.path=path;this.stat=stat;}
        void verify()throws Exception{
            need(path.getAbsoluteFile().equals(path.getCanonicalFile())&&same(stat,Os.lstat(path.getPath())),
                    "pinned file metadata changed");
        }
    }
    private static final class Parent {
        final int uid,pid;final long start;final String boot;
        Parent(int uid,int pid,long start,String boot){this.uid=uid;this.pid=pid;this.start=start;this.boot=boot;}
        static Parent read()throws Exception{
            int uid=android.os.Process.myUid(),pid=android.os.Process.myPid();
            need(uid>=10000&&pid>1,"ordinary application lifetime required");
            long start=WorkerGenerationProof.procStart(proc(new File("/proc/"+pid+"/stat"),8192),pid);
            String boot=new String(proc(new File("/proc/sys/kernel/random/boot_id"),80),StandardCharsets.US_ASCII);
            need(boot.matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\\n"),"boot identity unavailable");
            return new Parent(uid,pid,start,boot.substring(0,36));
        }
        void verify()throws Exception{
            Parent now=read();need(uid==now.uid&&pid==now.pid&&start==now.start&&boot.equals(now.boot),
                    "application lifetime changed");
        }
        WorkerGenerationProof.Expected expected(String task,String generation,String token)throws Exception{
            return new WorkerGenerationProof.Expected(task,generation,token,boot,uid,pid,start);
        }
        void bindEnvironment(Map<String,String> env,String task,String generation,String token)throws Exception{
            String[] expected={"v1",task,generation,token,Long.toString(start),boot};
            for(int i=0;i<expected.length;i++)need(expected[i].equals(env.get(WorkerGenerationProof.ENVIRONMENT[i])),
                    "independent parent/scope environment differs");
        }
    }
    private final class Round {
        final Task owner;final String generation,requestId,token;
        final CurrentFrame frame;final DecisionGrammar grammar;final Callback callback;
        final byte[] prompt,system,grammarBytes,taskOwner;
        final int maximumTokens;final long submitted,deadline;
        final OwnedWorkerCancellation cancellation;
        final File generationDirectory,directory;
        final Map<String,byte[]> originalInputs=new LinkedHashMap<>();
        final Map<String,Stamp> inputStamps=new LinkedHashMap<>(),sidecarStamps=new LinkedHashMap<>();
        final List<FileIdentity> modelFiles=new ArrayList<>(),runtimeFiles=new ArrayList<>();
        final List<String> validation=new ArrayList<>();
        final Map<String,Object> audit=new LinkedHashMap<>();
        Map<String,Object> currentFrame;
        Parent parent;OwnedGenerationScope scope;OwnedGenerationScope.Cleanup generationCleanup;
        WorkerGenerationProof.Identity identity;
        volatile Process process;
        volatile boolean finished,accepted,retired,cleanupKnown;
        boolean exitObserved,timedOut,logLimit,contractValid,parentCurrent,frameCurrent;
        Integer exitCode;
        long finishSubmitted,finishDeadline;
        String rawText="",failure;
        Stamp appReceipt,deliveryReceipt,rejectionReceipt,originalOwner,requestPending;
        Round(Task owner,String generation,String requestId,String token,CurrentFrame frame,
              DecisionGrammar grammar,byte[] prompt,byte[] system,int maximum,long timeout,Callback callback) {
            this.owner=owner;this.generation=generation;this.requestId=requestId;this.token=token;
            this.frame=frame;this.grammar=grammar;this.prompt=prompt;this.system=system;
            grammarBytes=grammar.text.getBytes(StandardCharsets.UTF_8);taskOwner=frame.taskOwnerEvidence();
            maximumTokens=maximum;this.callback=callback;
            submitted=System.nanoTime();deadline=Math.addExact(submitted,TimeUnit.MILLISECONDS.toNanos(timeout));
            generationDirectory=new File(new File(files,"runs"),generation);
            directory=new File(new File(generationDirectory,"vlm"),requestId);
            cancellation=owner.lease.prepareRequest(generation,token);
        }
        synchronized void beginFinish(){
            if(finishSubmitted==0){
                finishSubmitted=System.nanoTime();
                finishDeadline=Math.addExact(finishSubmitted,TimeUnit.MILLISECONDS.toNanos(cancellation.finishFutureMillis()));
            }
        }
    }

    @Override public synchronized void beginTask(String taskId) {
        if(task!=null)throw new IllegalStateException("prior visual task still owns the model slot");
        LocalModelEngine.TaskExternalLease lease=engine.reserveTaskExternal(taskId);
        Task value=new Task(lease);task=value;lastCleanup=null;
        try{
            MobiMindPrivateFiles.directory(files,false);
            MobiMindPrivateFiles.directory(new File(files,"runs"),false);
            MobiMindPrivateFiles.directory(value.directory,true);
            Map<String,Object> pending=new LinkedHashMap<>();
            pending.put("schema","hepta.vlm.task-pending.v1");pending.put("task_id",taskId);
            pending.put("task_generation",value.generation);pending.put("app_uid",android.os.Process.myUid());
            pending.put("app_pid",android.os.Process.myPid());pending.put("pending",true);
            pending.put("cleanup_known",false);pending.put("serial_generations",true);
            pending.put("automatic_resume",false);pending.put("automatic_retry",false);
            value.pendingReceipt=write(new File(value.directory,"vlm-task-pending.json"),json(pending),65536);
            value.pendingPublished=true;
        }catch(Exception failure){
            value.failed=true;value.publicationFailed=true;
            throw new IllegalStateException("visual task reservation could not be committed; slot retained",failure);
        }
    }
    @Override public void cancelTask(){
        Task value=task;if(value==null)return;
        Round round=value.current;if(round!=null)round.beginFinish();
        value.lease.cancel();
    }
    @Override public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,
                                     int maximum,long timeout,Callback callback){
        throw new IllegalArgumentException("visual inference requires the controller's live CurrentFrame");
    }
    @Override public Handle generateObserved(String prompt,String system,CurrentFrame frame,
            DecisionGrammar grammar,int maximum,long timeout,Callback callback) {
        if(frame==null||grammar==null||callback==null||maximum<1||maximum>256||timeout<1000||timeout>MAX_REQUEST_MILLIS)
            throw new IllegalArgumentException("current frame, current grammar and bounded visual request required");
        final byte[] promptBytes,systemBytes;
        try{
            promptBytes=text(prompt,131072);systemBytes=text(system,65536);
            need(!prompt.contains(VlmResultContract.MEDIA_MARKER)&&!system.contains(VlmResultContract.MEDIA_MARKER),
                    "reserved media marker supplied in original text");
            frame.requireCurrent();
        }catch(Exception invalid){throw new IllegalArgumentException("visual request has no valid current input",invalid);}
        final Task value=task;final Round round;
        if(value==null)throw new IllegalStateException("visual task is not reserved");
        synchronized(value){
            if(task!=value||value.ending||value.failed||value.publicationFailed||value.current!=null
                    ||!value.lease.current()||value.lease.isCancellationRequested()||value.rounds.size()>=MAX_ROUNDS)
                throw new IllegalStateException("visual task is retired, cancelled or already has a request");
            validateFrame(value,frame,grammar);
            String generation=id(),request=id(),token=id();
            if(generation.equals(value.generation)||generation.equals(request)||generation.equals(token)
                    ||request.equals(token)||request.equals(value.generation)||token.equals(value.generation)
                    ||generation.equals(value.taskId)||request.equals(value.taskId)||token.equals(value.taskId))
                throw new IllegalStateException("independent visual identities collided");
            round=new Round(value,generation,request,token,frame,grammar,promptBytes,systemBytes,maximum,timeout,callback);
            value.current=round;value.rounds.add(round);
        }
        try{engine.submitTaskExternal(value.lease,new Runnable(){public void run(){execute(round);}});}
        catch(RuntimeException rejected){
            round.failure="request_executor_rejected";value.failed=true;
            finishRequest(round,rejected);
        }
        return new Handle(){public void cancel(){
            round.beginFinish();value.lease.cancel();
        }};
    }
    private static void validateFrame(Task value,CurrentFrame frame,DecisionGrammar grammar) {
        if(!value.taskId.equals(frame.taskId)||grammar.authorization==null
                ||!value.taskId.equals(grammar.authorization.taskId)
                ||!frame.observationId.equals(grammar.observationId)||!frame.packageName.equals(grammar.currentPackage)
                ||!frame.ownerSha256.equals(grammar.authorization.authorization.instructionSha256)
                ||!frame.ownerSha256.equals(MobiMindContract.sha(frame.taskOwnerEvidence()))
                ||!grammar.sha256.equals(MobiMindContract.sha(grammar.text.getBytes(StandardCharsets.UTF_8))))
            throw new IllegalArgumentException("frame, original owner and current grammar differ");
        try{grammar.authorization.authorization.requireOwner(MobiMindContract.utf8(frame.taskOwnerEvidence()));}
        catch(Exception invalid){throw new IllegalArgumentException("original task owner differs",invalid);}
        if(value.ownerSha256==null){
            value.ownerSha256=frame.ownerSha256;value.backgroundGeneration=frame.backgroundGeneration;
            value.displayId=frame.displayId;
        }else if(!value.ownerSha256.equals(frame.ownerSha256)
                ||!value.backgroundGeneration.equals(frame.backgroundGeneration)||value.displayId.intValue()!=frame.displayId)
            throw new IllegalArgumentException("task frame migrated to a different owner/display generation");
    }
    private void requireCurrent(Round round,boolean beforeDeadline)throws Exception{
        Task value=round.owner;
        need(task==value&&value.current==round&&!value.ending&&!value.failed
                &&value.lease.current()&&!value.lease.isCancellationRequested(),"visual task no longer current");
        validateFrame(value,round.frame,round.grammar);
        round.frame.requireCurrent();
        if(beforeDeadline)need(System.nanoTime()<round.deadline,"original visual request deadline expired");
    }
    private void execute(Round round){
        Exception error=null;
        try{
            requireCurrent(round,true);
            prepareInputs(round);
            preflight(round);
            requireCurrent(round,true);
            round.parent=Parent.read();
            round.scope=new OwnedGenerationScope(files,new File((String)round.audit.get("native_directory"),VlmPins.WORKER),
                    round.generation,round.owner.taskId,round.token);
            File stdout=new File(round.directory,"stdout.log"),stderr=new File(round.directory,"stderr.log");
            MobiMindPrivateFiles.writeNew(stdout,new byte[0]);MobiMindPrivateFiles.writeNew(stderr,new byte[0]);
            File runner=new File((String)round.audit.get("native_directory"),VlmPins.WORKER);
            List<String> argv=Arrays.asList(runner.getPath(),"--expected-parent-pid",Integer.toString(round.parent.pid),
                    "--expected-app-uid",Integer.toString(round.parent.uid),"--app-files-dir",files.getPath(),
                    "--generation",round.generation,"--task-id",round.owner.taskId,"--request-id",round.requestId,
                    "--model-profile",configuration.profile.id);
            ProcessBuilder builder=new ProcessBuilder(argv).directory(round.directory).redirectOutput(stdout).redirectError(stderr);
            Map<String,String> env=builder.environment();round.scope.initialEnvironment(env);
            round.parent.bindEnvironment(env,round.owner.taskId,round.generation,round.token);
            String nativeDir=runner.getParent();
            env.put("HEPTA_LOCAL_NATIVE_LIB_DIR",nativeDir);env.put("LD_LIBRARY_PATH",nativeDir+":/vendor/lib64");
            env.put("ADSP_LIBRARY_PATH",nativeDir+";/vendor/lib/rfsa/adsp;/system/lib/rfsa/adsp;/dsp");
            env.put("GENIEX_PLUGIN_PATH",nativeDir);env.put("TMPDIR",round.directory.getPath());
            env.remove("LD_PRELOAD");env.remove("LD_AUDIT");env.remove("GENIEX_QAIRT_LIB");
            File kernels=kernelCacheDirectory(round.audit);
            env.put("GGML_OPENCL_KERNEL_CACHE_DIR",kernels.getPath());
            round.audit.put("argv",argv);round.audit.put("scope_environment_field_count",WorkerGenerationProof.ENVIRONMENT.length);
            round.audit.put("configured_ld_library_path",env.get("LD_LIBRARY_PATH"));
            round.audit.put("configured_adsp_library_path",env.get("ADSP_LIBRARY_PATH"));
            round.audit.put("linker_environment_is_not_runtime_maps_proof",true);
            for(FileIdentity stamp:round.runtimeFiles)stamp.verify();
            for(FileIdentity stamp:round.modelFiles)stamp.verify();
            checkMemory(round,"before_launch");
            requireCurrent(round,true);round.parent.verify();
            round.process=builder.start();
            round.cancellation.attach(round.process,round.generation,round.owner.taskId);
            round.owner.lease.attach(round.process,round.cancellation);
            supervise(round,stdout,stderr);
        }catch(Exception failure){error=failure;}
        finally{finishRequest(round,error);}
    }
    private File kernelCacheDirectory(Map<String,Object> audit)throws Exception{
        audit.put("kernel_cache_preparation_stage","context");
        File supplied=context.getCacheDir();
        audit.put("context_cache_directory",supplied==null?null:supplied.getPath());
        audit.put("context_cache_absolute_directory",supplied==null?null:supplied.getAbsolutePath());
        audit.put("canonical_app_data_directory",files.getParent());
        need(supplied!=null&&supplied.isAbsolute()&&"cache".equals(supplied.getName())
                &&supplied.getParentFile()!=null,"private kernel cache root unavailable");
        // Normalize only Android's app-data parent. Both leaves still pass the
        // original private-file guard, which rejects symlinks and foreign owners.
        audit.put("kernel_cache_preparation_stage","parent");
        File parent=supplied.getParentFile().getCanonicalFile();
        audit.put("canonical_context_cache_parent",parent.getPath());
        need(parent.equals(files.getParentFile()),"private kernel cache parent differs from app data");
        File cache=new File(parent,"cache");
        audit.put("kernel_cache_preparation_stage","cache");
        audit.put("selected_cache_canonical_directory",cache.getCanonicalPath()); // Evidence only; never the selected path.
        MobiMindPrivateFiles.directory(cache,false);
        File kernels=new File(cache,"hepta-vlm-opencl-kernels");
        audit.put("kernel_cache_preparation_stage","kernel_child");
        MobiMindPrivateFiles.directory(kernels,false);
        audit.put("configured_opencl_kernel_cache_directory",kernels.getPath());
        audit.put("kernel_cache_preparation_stage","ready");
        return kernels;
    }
    private void preflight(Round round)throws Exception{
        need(PACKAGE.equals(context.getPackageName())&&android.os.Process.isApplicationUid(android.os.Process.myUid()),
                "ordinary Hepta package/UID required");
        PackageInfo info=context.getPackageManager().getPackageInfo(PACKAGE,PackageManager.GET_PERMISSIONS);
        if(info.requestedPermissions!=null)for(String permission:info.requestedPermissions)
            need(!"android.permission.INTERNET".equals(permission),"visual APK must not declare INTERNET");
        round.audit.put("internet_permission_declared",false);
        checkMemory(round,"before");
        File model=new File(files,"gui-owl-model");
        need(model.equals(model.getCanonicalFile()),"model directory aliases");MobiMindPrivateFiles.directory(model,false);
        model(round,new File(model,configuration.profile.fileName),configuration.profile.bytes);
        model(round,new File(model,VlmPins.PROJECTOR),VlmPins.PROJECTOR_BYTES);
        File installed=new File(context.getApplicationInfo().nativeLibraryDir);
        need(installed.isAbsolute()&&installed.equals(installed.getCanonicalFile())
                &&installed.getPath().startsWith("/data/app/"),"canonical installed APK native directory required");
        round.audit.put("native_directory",installed.getPath());round.audit.put("model_directory",model.getPath());
        List<Map<String,Object>> runtime=new ArrayList<>();
        runtime.add(runtime(round,installed,VlmPins.WORKER,VlmPins.WORKER_BYTES,VlmPins.WORKER_SHA));
        for(UiVenusPins.FilePin pin:UiVenusPins.sdk())runtime.add(runtime(round,installed,pin.name,pin.bytes,pin.sha256));
        need(new File(installed,VlmPins.WORKER).canExecute(),"installed pinned VLM worker is not executable");
        round.audit.put("runtime_files",runtime);round.audit.put("runtime_files_full_sha_verified_by_app",true);
        round.audit.put("model_sha256_expected",configuration.profile.sha256);
        round.audit.put("projector_sha256_expected",VlmPins.PROJECTOR_SHA);
        round.audit.put("model_full_hash_authority","pinned_native_worker_held_fds_per_request");
    }
    private void checkMemory(Round round,String phase)throws Exception{
        ActivityManager.MemoryInfo info=new ActivityManager.MemoryInfo();
        Object service=context.getSystemService(Context.ACTIVITY_SERVICE);
        need(service instanceof ActivityManager,"ActivityManager memory measurement unavailable");
        ((ActivityManager)service).getMemoryInfo(info);
        MemoryAvailability memory=MemoryAvailability.read(info.availMem,info.totalMem,info.lowMemory);
        round.audit.put("available_memory_"+phase+"_bytes",memory.availableBytes);
        round.audit.put("available_memory_"+phase+"_source",memory.source);
        round.audit.put("minimum_available_memory_bytes",MIN_AVAILABLE_BYTES);
        round.audit.put("memory_threshold_is_not_peak_memory_proof",true);
        need(memory.admits(MIN_AVAILABLE_BYTES),"available physical memory below 6 GiB or invalid/lowMemory measurement");
    }
    private void model(Round round,File path,long expectedBytes)throws Exception{
        need(path.equals(path.getCanonicalFile()),"model file aliases");StructStat st=Os.lstat(path.getPath());
        need(OsConstants.S_ISREG(st.st_mode)&&st.st_uid==android.os.Process.myUid()&&st.st_nlink==1
                &&(st.st_mode&0777)==0600&&st.st_size==expectedBytes,"complete private model metadata differs");
        round.modelFiles.add(new FileIdentity(path,st));
    }
    private Map<String,Object> runtime(Round round,File dir,String name,long size,String sha)throws Exception{
        requireCurrent(round,true);need(size>0&&size<=Integer.MAX_VALUE,"runtime size bound");
        File path=new File(dir,name);MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,(int)size,false);
        String actual=MobiMindContract.sha(read.bytes);
        need(read.bytes.length==size&&sha.equals(actual),"installed runtime hash differs: "+name);
        read.unchangedPath();round.runtimeFiles.add(new FileIdentity(path,read.stat));
        Map<String,Object> out=new LinkedHashMap<>();out.put("file",name);out.put("bytes",size);out.put("sha256",actual);return out;
    }
    private void reserveRoundDirectory(Round round)throws Exception{
        MobiMindPrivateFiles.directory(files,false);MobiMindPrivateFiles.directory(new File(files,"runs"),false);
        MobiMindPrivateFiles.directory(round.generationDirectory,true);
        MobiMindPrivateFiles.directory(new File(round.generationDirectory,"vlm"),true);
        MobiMindPrivateFiles.directory(round.directory,true);
    }
    private void prepareInputs(Round round)throws Exception{
        reserveRoundDirectory(round);
        MobiMindPrivateFiles.Read original=MobiMindPrivateFiles.read(round.frame.image,VlmPins.IMAGE_BYTES_LIMIT,true);
        need(round.frame.imageSha256.equals(MobiMindContract.sha(original.bytes)),"original current screenshot hash differs");
        original.unchangedPath();
        Map<String,Object> owner=new LinkedHashMap<>();
        owner.put("schema","hepta.vlm.current-frame.v1");owner.put("task_id",round.owner.taskId);
        owner.put("generation",round.generation);owner.put("request_id",round.requestId);owner.put("scope_token",round.token);
        owner.put("observation_id",round.frame.observationId);owner.put("background_generation",round.frame.backgroundGeneration);
        owner.put("task_owner_sha256",round.frame.ownerSha256);owner.put("image_sha256",round.frame.imageSha256);
        owner.put("grammar_sha256",round.grammar.sha256);owner.put("image_width",round.frame.width);
        owner.put("image_height",round.frame.height);owner.put("package_name",round.frame.packageName);
        owner.put("display_id",round.frame.displayId);owner.put("window_id",round.frame.windowId);
        owner.put("rotation",round.frame.rotation);owner.put("captured_elapsed_ms",round.frame.capturedElapsedMillis);
        round.currentFrame=Collections.unmodifiableMap(owner);
        byte[] ownerBytes=json(owner);
        Map<String,Object> request=new LinkedHashMap<>();
        request.put("schema","hepta.vlm.request.v1");request.put("profile",configuration.profile.id);
        request.put("request_id",round.requestId);request.put("generation",round.generation);request.put("task_id",round.owner.taskId);
        request.put("owner_sha256",MobiMindContract.sha(ownerBytes));request.put("prompt_sha256",MobiMindContract.sha(round.prompt));
        request.put("system_sha256",MobiMindContract.sha(round.system));request.put("image_sha256",round.frame.imageSha256);
        request.put("grammar_sha256",round.grammar.sha256);request.put("max_tokens",round.maximumTokens);
        request.put("deadline_monotonic_ns",round.deadline);request.put("image_width",round.frame.width);
        request.put("image_height",round.frame.height);
        input(round,"owner.json",ownerBytes,131072);input(round,"prompt.txt",round.prompt,131072);
        input(round,"system.txt",round.system,65536);input(round,"screen.png",original.bytes,VlmPins.IMAGE_BYTES_LIMIT);
        input(round,"decision.gbnf",round.grammarBytes,262144);input(round,"request.json",json(request),16384);
        round.originalOwner=write(new File(round.directory,"task-owner.txt"),round.taskOwner,1600);
        Map<String,Object> pending=base(round,"hepta.vlm.request-pending.v1");
        pending.put("pending",true);pending.put("process_started",false);pending.put("cleanup_known",false);
        pending.put("original_deadline_monotonic_ns",round.deadline);pending.put("automatic_retry",false);
        round.requestPending=write(new File(round.directory,"app-request-pending.json"),json(pending),65536);
        inspectOriginalPixels(round,original.bytes);
    }
    /** Exact pixel facts only; no darkness ratio, crop, rewrite or image replacement. */
    static final class PixelFacts {
        final int width,height;
        private int rows;
        private boolean rgbZero=true,transparent=true;
        PixelFacts(int width,int height){
            if(width<1||height<1||width>8192||height>8192||(long)width*height>24000000L)
                throw new IllegalArgumentException("bounded original image geometry required");
            this.width=width;this.height=height;
        }
        void row(int[] pixels){
            if(pixels==null||pixels.length!=width||rows>=height)throw new IllegalArgumentException("complete original row required");
            for(int pixel:pixels){
                if((pixel&0x00ffffff)!=0)rgbZero=false;
                if((pixel>>>24)!=0)transparent=false;
            }
            rows++;
        }
        Map<String,Object> evidence(){
            if(rows!=height)throw new IllegalStateException("full original pixel scan required");
            Map<String,Object> out=new LinkedHashMap<>();out.put("schema","hepta.vlm.original-pixel-facts.v1");
            out.put("width",width);out.put("height",height);out.put("pixels_scanned",(long)width*height);
            out.put("all_rgb_zero",rgbZero);out.put("fully_transparent",transparent);
            out.put("available",!rgbZero&&!transparent);out.put("pixel_inspection_only",true);
            out.put("input_image_reencoded",false);out.put("ratio_threshold_used",false);return out;
        }
    }
    private void inspectOriginalPixels(Round round,byte[] png)throws Exception{
        Bitmap bitmap=null;
        try{
            BitmapFactory.Options options=new BitmapFactory.Options();
            options.inPreferredConfig=Bitmap.Config.ARGB_8888;options.inScaled=false;options.inPremultiplied=false;
            bitmap=BitmapFactory.decodeByteArray(png,0,png.length,options);
            need(bitmap!=null&&bitmap.getWidth()==round.frame.width&&bitmap.getHeight()==round.frame.height,
                    "VISUAL_FRAME_UNAVAILABLE: original PNG could not be decoded with its recorded geometry");
            PixelFacts scan=new PixelFacts(bitmap.getWidth(),bitmap.getHeight());
            int[] row=new int[scan.width];
            for(int y=0;y<scan.height;y++){
                bitmap.getPixels(row,0,scan.width,0,y,scan.width,1);scan.row(row);
            }
            Map<String,Object> facts=scan.evidence();facts.put("original_png_sha256",round.frame.imageSha256);
            facts.put("observation_id",round.frame.observationId);facts.put("display_id",round.frame.displayId);
            facts.put("captured_elapsed_ms",round.frame.capturedElapsedMillis);
            round.audit.put("original_frame_quality",facts);
            need(Boolean.TRUE.equals(facts.get("available")),
                    "VISUAL_FRAME_UNAVAILABLE: original frame is entirely RGB-zero or fully transparent");
        }catch(Exception unavailable){
            round.audit.put("visual_frame_unavailable",true);
            if(!round.audit.containsKey("original_frame_quality"))round.audit.put("original_frame_quality_error",unavailable.getClass().getSimpleName());
            throw unavailable;
        }finally{if(bitmap!=null)bitmap.recycle();}
    }
    private static void input(Round round,String name,byte[] bytes,int limit)throws Exception{
        Stamp stamp=write(new File(round.directory,name),bytes,limit);
        round.originalInputs.put(name,bytes);round.inputStamps.put(name,stamp);
    }
    private void supervise(Round round,File stdout,File stderr)throws Exception{
        while(true){
            long now=System.nanoTime();
            if(now>=round.deadline)round.timedOut=true;
            if(stdout.length()>LOG_LIMIT||stderr.length()>LOG_LIMIT)round.logLimit=true;
            if(round.owner.lease.isCancellationRequested()||round.timedOut||round.logLimit){
                round.beginFinish();round.owner.lease.cancel();
                OwnedWorkerCancellation.Exit stopped=round.cancellation.awaitCancellation();
                round.exitObserved=stopped.observed;round.exitCode=stopped.code;break;
            }
            long wait=Math.min(TimeUnit.MILLISECONDS.toNanos(100),round.deadline-now);
            if(round.process.waitFor(wait,TimeUnit.NANOSECONDS)){
                round.exitObserved=true;round.exitCode=round.process.exitValue();
                round.beginFinish();break;
            }
        }
        if(System.nanoTime()>=round.deadline||Integer.valueOf(124).equals(round.exitCode))round.timedOut=true;
        if(stdout.length()>LOG_LIMIT||stderr.length()>LOG_LIMIT)round.logLimit=true;
    }
    private void finishRequest(Round round,Exception failure){
        Task value=round.owner;round.beginFinish();
        if(failure!=null)round.failure=describe(failure);
        try{
            if(round.process!=null&&!round.exitObserved){
                round.cancellation.attach(round.process,round.generation,value.taskId);
                value.lease.cancel();
                OwnedWorkerCancellation.Exit exit=round.cancellation.awaitCancellation();
                round.exitObserved=exit.observed;round.exitCode=exit.code;
            }
            if(round.process!=null&&round.exitObserved&&round.scope!=null
                    &&value.lease.ownsRequest(round.generation,round.token,round.cancellation,round.process)){
                round.generationCleanup=round.scope.finish(true,round.finishSubmitted,round.finishDeadline);
            }
            round.cleanupKnown=round.process==null||round.exitObserved&&round.generationCleanup!=null&&round.generationCleanup.known;
            if(round.parent!=null){try{round.parent.verify();round.parentCurrent=true;}catch(Exception invalid){round.validation.add("independent_parent_lifetime");}}
            try{requireCurrent(round,true);round.frameCurrent=true;}catch(Exception invalid){round.validation.add("current_frame_ownership");}
            if(round.process!=null)verifyResult(round);
            else round.validation.add("native_process_not_started");
            if(round.timedOut)round.validation.add("original_request_deadline");
            if(round.logLimit)round.validation.add("native_log_bound");
            if(failure!=null)round.validation.add("request_failed_before_acceptance");
            round.contractValid=round.validation.isEmpty();
            round.cleanupKnown=round.cleanupKnown&&System.nanoTime()<=round.finishDeadline;
            publishRequest(round);
            boolean candidate=round.contractValid&&round.cleanupKnown&&!value.failed&&!value.ending
                    &&value.lease.current()&&!value.lease.isCancellationRequested();
            if(candidate)try{requireCurrent(round,true);}catch(Exception changed){candidate=false;round.failure="current_frame_changed_before_delivery";}
            Map<String,Object> delivery=base(round,"hepta.vlm.request-delivery.v1");
            delivery.put("app_receipt_sha256",round.appReceipt.sha256);delivery.put("success_admitted",candidate);
            delivery.put("callback_already_delivered",false);delivery.put("cleanup_known",round.cleanupKnown);
            delivery.put("model_output_dispatched",false);delivery.put("failure",round.failure);
            round.deliveryReceipt=write(new File(round.directory,"app-delivery.json"),json(delivery),65536);
            if(round.cleanupKnown&&System.nanoTime()<=round.finishDeadline){
                value.lease.retireRequest(round.process,round.exitObserved,round.exitCode,round.generationCleanup,true);
                round.retired=true;
            }else round.cleanupKnown=false;
            if(candidate&&round.retired){
                try{requireCurrent(round,true);round.accepted=true;}
                catch(Exception changed){
                    round.failure="current_frame_changed_at_callback";
                    Map<String,Object> refusal=base(round,"hepta.vlm.request-delivery-rejection.v1");
                    refusal.put("delivery_receipt_sha256",round.deliveryReceipt.sha256);
                    refusal.put("success_delivered",false);refusal.put("reason",round.failure);
                    round.rejectionReceipt=write(new File(round.directory,"app-delivery-rejection.json"),json(refusal),65536);
                }
            }
        }catch(Exception error){
            round.failure=describe(error);round.accepted=false;round.cleanupKnown=false;
            value.publicationFailed=true;
        }finally{
            round.originalInputs.clear(); // Full PNGs are not retained across every task step.
            synchronized(value){
                round.finished=true;
                if(round.retired&&value.current==round)value.current=null;
                if(!round.accepted)value.failed=true;
            }
            try{
                if(round.accepted)round.callback.onSuccess(round.rawText,round.requestId);
                else round.callback.onFailure(round.failure==null?"visual request was not accepted: "+round.validation:round.failure,round.cleanupKnown);
            }catch(RuntimeException callbackFailure){
                round.accepted=false;value.failed=true;
                // Client code cannot release ownership or trigger another generation.
            }
        }
    }
    private void verifyResult(Round round)throws Exception{
        if(round.parent==null||round.scope==null){round.validation.add("independent_scope_unavailable");return;}
        try{
            File path=new File(round.generationDirectory,"worker-generation.identity");
            MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,WorkerGenerationProof.IDENTITY_LIMIT,true);
            round.identity=WorkerGenerationProof.identity(read.bytes,round.parent.expected(round.owner.taskId,round.generation,round.token));
            round.originalInputs.put("worker-generation.identity",read.bytes);
            round.inputStamps.put("worker-generation.identity",new Stamp(path,WorkerGenerationProof.IDENTITY_LIMIT,read.bytes));
            read.unchangedPath();
        }catch(Exception missing){round.validation.add("independent_generation_identity");}
        Map<String,byte[]> sidecars=new LinkedHashMap<>();
        for(String name:VlmResultContract.requiredSidecarNames()){
            int bound=sidecarLimit(name);
            try{
                File path=new File(round.directory,name);MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,bound,true);
                sidecars.put(name,read.bytes);round.sidecarStamps.put(name,new Stamp(path,bound,read.bytes));read.unchangedPath();
            }catch(Exception missing){round.validation.add("sidecar_unavailable:"+name);}
        }
        for(Stamp stamp:round.inputStamps.values())stamp.verify();
        for(FileIdentity stamp:round.modelFiles)stamp.verify();
        for(FileIdentity stamp:round.runtimeFiles)stamp.verify();
        if(round.identity==null||!sidecars.containsKey("native-result.json"))return;
        Map<String,Object> nativeResult=VlmResultContract.jsonObject(sidecars.get("native-result.json"));
        round.audit.put("native_receipt",nativeResult);
        OwnedWorkerCancellation.Snapshot cancelled=round.cancellation.snapshot();
        boolean owns=round.owner.lease.ownsRequest(round.generation,round.token,round.cancellation,round.process)
                &&round.frameCurrent;
        VlmResultContract.Lifecycle lifecycle=new VlmResultContract.Lifecycle(round.exitObserved,
                round.generationCleanup!=null&&round.generationCleanup.known,
                round.generationCleanup!=null&&round.generationCleanup.unforced()&&cancelled.forceAttempts==0,
                round.parentCurrent,owns,round.owner.lease.isCancellationRequested());
        VlmResultContract.Expected expected=new VlmResultContract.Expected(round.owner.taskId,round.generation,round.requestId,
                round.token,round.parent.uid,round.parent.pid,(int)round.identity.leaderPid,round.parent.start,
                round.identity.leaderStart,round.parent.boot,VlmResultContract.GUI_OWL_4B,round.originalInputs,
                round.currentFrame,round.taskOwner,System.nanoTime(),lifecycle);
        round.validation.addAll(VlmResultContract.verify(nativeResult,sidecars,expected,
                round.exitObserved&&round.exitCode!=null?round.exitCode.intValue():-1));
        if(sidecars.containsKey("raw.txt"))round.rawText=MobiMindContract.utf8(sidecars.get("raw.txt"));
    }
    private void publishRequest(Round round)throws Exception{
        if(!round.directory.isDirectory()){
            // A preflight rejection has no child and still receives create-only evidence.
            need(round.process==null,"started visual process lost its private directory");reserveRoundDirectory(round);
        }
        Map<String,Object> receipt=base(round,"hepta.vlm.app-request.v1");
        receipt.putAll(round.audit);receipt.put("profile",configuration.profile.id);
        receipt.put("serial_generations",true);receipt.put("context_tokens",8192);receipt.put("threads",4);
        receipt.put("lm_device_requested","HTP0");receipt.put("vision_device_requested","GPUOpenCL");
        receipt.put("maximum_output_tokens",round.maximumTokens);receipt.put("original_deadline_monotonic_ns",round.deadline);
        receipt.put("submitted_monotonic_ns",round.submitted);receipt.put("finished_monotonic_ns",System.nanoTime());
        receipt.put("finisher_submitted_monotonic_ns",round.finishSubmitted);
        receipt.put("finisher_deadline_monotonic_ns",round.finishDeadline);
        receipt.put("process_started",round.process!=null);receipt.put("process_exit_observed",round.exitObserved);
        receipt.put("actual_exit_code",round.exitCode);receipt.put("cleanup_known",round.cleanupKnown);
        receipt.put("generation_cleanup",round.generationCleanup==null?null:VlmResultContract.jsonObject(
                round.generationCleanup.evidence.toString().getBytes(StandardCharsets.UTF_8)));
        receipt.put("native_contract_valid",round.contractValid);receipt.put("validation_errors",new ArrayList<>(round.validation));
        receipt.put("failure",round.failure);receipt.put("timeout_observed",round.timedOut);receipt.put("log_limit_observed",round.logLimit);
        receipt.put("cancellation",cancellation(round.cancellation.snapshot()));
        receipt.put("original_inputs",stamps(round.inputStamps));receipt.put("native_sidecars",stamps(round.sidecarStamps));
        receipt.put("original_task_owner",round.originalOwner==null?null:round.originalOwner.evidence());
        receipt.put("request_pending",round.requestPending==null?null:round.requestPending.evidence());
        receipt.put("image_transformed_by_app",false);receipt.put("automatic_retry",false);receipt.put("automatic_restart",false);
        receipt.put("automatic_device_fallback",false);receipt.put("external_model",false);
        receipt.put("actions_dispatched",false);receipt.put("business_completion_verified",false);
        round.appReceipt=write(new File(round.directory,"app-receipt.json"),json(receipt),RECEIPT_LIMIT);
    }
    @Override public synchronized TaskCleanup endTask(String expectedTaskId){
        TaskCleanup.requireTaskId(expectedTaskId);
        final Task value=task;
        if(value==null){
            // A bootstrap failure may occur before beginTask. Preserve repeated
            // cleanup for its actual task without borrowing the previous task.
            TaskCleanup previous=lastCleanup;
            return previous!=null&&expectedTaskId.equals(previous.taskId)
                    ?TaskCleanup.requireTask(expectedTaskId,previous):TaskCleanup.noWorker(expectedTaskId);
        }
        if(!expectedTaskId.equals(value.taskId))
            throw new IllegalStateException("visual model slot is owned by a different task");
        return TaskCleanup.requireTask(expectedTaskId,endTask());
    }
    @Override public TaskCleanup endTask(){
        final Task value=task;if(value==null)return lastCleanup==null?TaskCleanup.noWorker():lastCleanup;
        Future<?> finisher;
        try{
            synchronized(value){
                if(value.cleanup!=null)return value.cleanup;
                value.ending=true;value.lease.endRequests();
                Round current=value.current;
                if(current!=null&&!current.finished){current.beginFinish();value.lease.cancel();}
                if(value.finisher==null){
                    if(value.finishSubmitted!=0)throw new IllegalStateException("task finisher submission already attempted");
                    value.finishSubmitted=System.nanoTime();
                    value.finishDeadline=Math.addExact(value.finishSubmitted,
                            TimeUnit.MILLISECONDS.toNanos(OwnedWorkerCancellation.FINISH_FUTURE_MILLIS));
                    if(current!=null&&!current.finished&&current.finishDeadline!=0)
                        value.finishDeadline=Math.min(value.finishDeadline,current.finishDeadline);
                    value.finisher=engine.submitTaskExternal(value.lease,new Runnable(){public void run(){finishTask(value);}});
                }
                finisher=value.finisher;
            }
            finisher.get(Math.max(0,value.finishDeadline-System.nanoTime()),TimeUnit.NANOSECONDS);
            if(value.cleanup==null)throw new IOException("aggregate task terminal was not published");
            return value.cleanup;
        }catch(Exception failure){
            if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
            synchronized(value){
                if(value.cleanup!=null&&value.cleanup.cleanupKnown)return value.cleanup;
                value.finishExpired=true;value.failed=true;
            }
            value.lease.cancel();
            return unknown(value);
        }
    }
    private void finishTask(Task value){
        boolean anyStarted=false,allExited=true,allClean=value.pendingPublished&&!value.publicationFailed;
        boolean allAccepted=!value.rounds.isEmpty()&&!value.failed&&!value.lease.isCancellationRequested();
        Integer firstNonzero=null;String receiptHash=null;List<Map<String,Object>> rows=new ArrayList<>();
        try{
            need(value.pendingReceipt!=null,"original task reservation missing");value.pendingReceipt.verify();
            for(Round round:value.rounds){
                need(System.nanoTime()<=value.finishDeadline&&!value.finishExpired,"original task finisher budget expired");
                anyStarted|=round.process!=null;
                if(round.process!=null){
                    allExited&=round.exitObserved&&!round.process.isAlive()&&round.exitCode!=null
                            &&round.process.exitValue()==round.exitCode.intValue();
                    if(round.exitCode!=null&&round.exitCode.intValue()!=0&&firstNonzero==null)firstNonzero=round.exitCode;
                }
                allClean&=round.finished&&round.retired&&round.cleanupKnown;
                allAccepted&=round.accepted&&round.contractValid&&round.exitObserved&&Integer.valueOf(0).equals(round.exitCode);
                need(round.appReceipt!=null&&round.deliveryReceipt!=null,"request terminal publication missing");
                round.appReceipt.verify();round.deliveryReceipt.verify();
                if(round.rejectionReceipt!=null)round.rejectionReceipt.verify();
                if(round.originalOwner!=null)round.originalOwner.verify();
                if(round.requestPending!=null)round.requestPending.verify();
                for(Stamp stamp:round.inputStamps.values())stamp.verify();
                for(Stamp stamp:round.sidecarStamps.values())stamp.verify();
                if(round.generationCleanup!=null&&round.generationCleanup.known){
                    String path=round.generationCleanup.evidence.getString("native_receipt_file");
                    String hash=round.generationCleanup.evidence.getString("native_receipt_sha256");
                    byte[] raw=MobiMindPrivateFiles.read(new File(path),WorkerGenerationProof.RECEIPT_LIMIT,true).bytes;
                    need(hash.equals(MobiMindContract.sha(raw)),"original generation cleanup receipt changed");
                }
                Map<String,Object> row=base(round,"hepta.vlm.serial-generation-summary.v1");
                row.put("app_receipt",round.appReceipt.evidence());row.put("delivery_receipt",round.deliveryReceipt.evidence());
                row.put("delivery_rejection",round.rejectionReceipt==null?null:round.rejectionReceipt.evidence());
                row.put("native_receipt",round.sidecarStamps.containsKey("native-result.json")
                        ?round.sidecarStamps.get("native-result.json").evidence():null);
                row.put("process_started",round.process!=null);row.put("process_exit_observed",round.exitObserved);
                row.put("actual_exit_code",round.exitCode);row.put("cleanup_known",round.cleanupKnown);
                row.put("native_contract_valid",round.contractValid);row.put("success_callback_returned",round.accepted);
                row.put("generation_cleanup",round.generationCleanup==null?null:VlmResultContract.jsonObject(
                        round.generationCleanup.evidence.toString().getBytes(StandardCharsets.UTF_8)));
                rows.add(row);
            }
            allClean&=!value.lease.requestPending()&&value.lease.current()&&!value.finishExpired;
            allAccepted&=anyStarted&&allExited&&allClean&&!value.lease.isCancellationRequested();
            Map<String,Object> aggregate=new LinkedHashMap<>();
            aggregate.put("schema",TASK_SCHEMA);aggregate.put("task_id",value.taskId);
            aggregate.put("task_generation",value.generation);aggregate.put("generation_semantics","logical_task_reservation");
            aggregate.put("serial_generations",true);aggregate.put("requests",rows);
            aggregate.put("original_pending",value.pendingReceipt.evidence());
            aggregate.put("process_started",anyStarted);aggregate.put("all_started_process_exits_observed",anyStarted&&allExited);
            aggregate.put("cleanup_known",allClean);aggregate.put("all_request_bindings_valid",allAccepted);
            aggregate.put("aggregate_exit_code",allAccepted?Integer.valueOf(0):firstNonzero);
            aggregate.put("aggregate_exit_zero_semantics","all_serial_requests_accepted_with_actual_exit_zero_and_generation_cleanup");
            aggregate.put("cancel_requested",value.lease.isCancellationRequested());
            aggregate.put("finisher_submitted_monotonic_ns",value.finishSubmitted);
            aggregate.put("finisher_deadline_monotonic_ns",value.finishDeadline);
            aggregate.put("published_monotonic_ns",System.nanoTime());
            aggregate.put("native_task_session_receipt_fabricated",false);aggregate.put("automatic_retry",false);
            aggregate.put("automatic_restart",false);aggregate.put("cross_task_reuse",false);
            aggregate.put("external_model",false);aggregate.put("business_completion_verified",false);
            Stamp receipt=write(new File(value.directory,"vlm-task-terminal.json"),json(aggregate),8*1024*1024);
            receiptHash=receipt.sha256;
            synchronized(value){
                allClean&=!value.finishExpired&&System.nanoTime()<=value.finishDeadline;
                allAccepted&=allClean&&!value.lease.isCancellationRequested();
                TaskCleanup proof=new TaskCleanup(allClean,anyStarted,anyStarted&&allExited,
                        allAccepted?Integer.valueOf(0):firstNonzero,value.generation,value.taskId,allAccepted,receiptHash);
                if(allClean)value.lease.releaseAfterTerminalPublication(true);
                value.cleanup=proof;
                if(allClean){lastCleanup=proof;task=null;}
            }
        }catch(Exception failure){
            value.failed=true;value.publicationFailed=true;
            TaskCleanup observed=unknown(value);
            value.cleanup=new TaskCleanup(false,observed.processStarted,observed.processExitObserved,observed.exitCode,
                    value.generation,value.taskId,false,receiptHash);
        }
    }
    private static TaskCleanup unknown(Task value){
        boolean started=false,exited=true;Integer nonzero=null;
        synchronized(value){for(Round round:value.rounds){
            started|=round.process!=null;
            if(round.process!=null){exited&=round.exitObserved;if(round.exitCode!=null&&round.exitCode.intValue()!=0)nonzero=round.exitCode;}
        }}
        return new TaskCleanup(false,started,started&&exited,nonzero,value.generation,value.taskId,false,null);
    }
    private static Map<String,Object> base(Round round,String schema){
        Map<String,Object> out=new LinkedHashMap<>();out.put("schema",schema);out.put("task_id",round.owner.taskId);
        out.put("task_generation",round.owner.generation);out.put("generation",round.generation);
        out.put("request_id",round.requestId);out.put("scope_token",round.token);
        out.put("owner_sha256",round.frame.ownerSha256);out.put("observation_id",round.frame.observationId);
        out.put("background_generation",round.frame.backgroundGeneration);return out;
    }
    private static Map<String,Object> cancellation(OwnedWorkerCancellation.Snapshot snapshot){
        Map<String,Object> out=new LinkedHashMap<>();out.put("schema","hepta.owned-worker-cancellation.v1");
        out.put("worker_generation",snapshot.generation);out.put("task_id",snapshot.taskId);
        out.put("requested",snapshot.requested);out.put("process_bound",snapshot.processBound);
        out.put("policy",snapshot.policy);out.put("cooperative_grace_ms",snapshot.cooperativeGraceMillis);
        out.put("force_observation_ms",OwnedWorkerCancellation.FORCE_OBSERVATION_MILLIS);
        out.put("finish_future_ms",snapshot.finishFutureMillis);out.put("term_destroy_attempts",snapshot.termAttempts);
        out.put("force_destroy_attempts",snapshot.forceAttempts);out.put("term_destroy_returned",snapshot.termReturned);
        out.put("force_destroy_returned",snapshot.forceReturned);out.put("signal_error",snapshot.signalError);
        out.put("exit_observed_by_cancellation_wait",snapshot.exitObserved);out.put("cancellation_wait_exit_code",snapshot.exitCode);
        out.put("normal_process_wait_is_recorded_separately",true);return out;
    }
    private static Map<String,Object> stamps(Map<String,Stamp> values){
        Map<String,Object> out=new LinkedHashMap<>();for(Map.Entry<String,Stamp> row:values.entrySet())out.put(row.getKey(),row.getValue().evidence());return out;
    }
    private static int sidecarLimit(String name){
        if("native-result.json".equals(name))return 262144;
        if("raw.txt".equals(name)||"gguf-chat-template.jinja".equals(name))return 65536;
        return 1048576;
    }
    private static Stamp write(File path,byte[] contents,int limit)throws Exception{
        need(contents.length<=limit,"private evidence exceeds bound");
        MobiMindPrivateFiles.writeNew(path,contents);
        MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(path,limit,true);
        need(Arrays.equals(contents,read.bytes),"durable private evidence readback differs");read.unchangedPath();
        return new Stamp(path,limit,read.bytes);
    }
    private static byte[] json(Map<String,?> value){return VlmResultContract.canonicalJson(value).getBytes(StandardCharsets.UTF_8);}
    private static byte[] text(String value,int limit)throws Exception{
        need(value!=null&&!value.isEmpty()&&value.indexOf('\0')<0,"original text missing or contains NUL");
        ByteBuffer encoded=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
        byte[] bytes=new byte[encoded.remaining()];encoded.get(bytes);need(bytes.length<=limit,"original text exceeds bound");return bytes;
    }
    private static byte[] proc(File path,int limit)throws IOException{
        try(FileInputStream in=new FileInputStream(path);ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[1024];for(int n;(n=in.read(buffer))!=-1;){
                if(out.size()+n>limit)throw new IOException("bounded process evidence exceeded");out.write(buffer,0,n);
            }return out.toByteArray();
        }
    }
    private static boolean same(StructStat a,StructStat b){
        return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_uid==b.st_uid
                &&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink&&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;
    }
    private static void need(boolean value,String reason)throws IOException{if(!value)throw new IOException(reason);}
    private static String describe(Exception failure){return failure.getClass().getSimpleName()+": "+String.valueOf(failure.getMessage());}
}
