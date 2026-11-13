package org.trillionnium.hepta.local;

import android.app.ActivityManager;
import android.content.Context;
import android.os.SystemClock;
import android.system.Os;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** One on-device LFM3 request at a time. No network, shell, or phone action API. */
public final class LocalModelEngine implements AutoCloseable {
    public static final long MIN_AVAILABLE_BYTES = 3L * 1024 * 1024 * 1024;
    private static final int TEXT_LIMIT = 65536;
    private static final int OUTPUT_LIMIT = 1024 * 1024;
    private final Context context;
    private final File files;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final AtomicReference<RunHandle> PROCESS_ACTIVE = new AtomicReference<>();
    // Only flags/CAS/queue reservation run under this gate; no native signal, IO or exit wait.
    private static final TaskCancellationQueue ACTIVE_CANCELLATION = TaskCancellationQueue.processQueue();
    private static final Object PROCESS_ADMISSION = ACTIVE_CANCELLATION.admissionMonitor();
    private final AtomicReference<RunHandle> active = new AtomicReference<>();
    private final AtomicReference<WarmTask> warmActive = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private volatile Result lastResult;
    private volatile TaskCancellationQueue.Ticket lastCancellation;
    private final ModelFileVerifier modelVerifier = new ModelFileVerifier();
    private final LocalRuntimeConfig configuration;
    private final String configurationError;

    public LocalModelEngine(Context context) {
        this.context = context.getApplicationContext();
        this.files = this.context.getFilesDir();
        LocalRuntimeConfig selected = LocalRuntimeConfig.defaults();
        String failure = null;
        try { selected = readConfiguration(); }
        catch (Exception error) { failure = error.getMessage(); }
        this.configuration = selected;
        this.configurationError = failure;
    }

    public static final class Request {
        public final String prompt, systemPrompt;
        public final File imageOrNull;
        public final DecisionGrammar controllerGrammar;
        public final int maxTokens;
        public final long timeoutMs;
        public Request(String prompt, String systemPrompt, File imageOrNull, int maxTokens, long timeoutMs) {
            this(prompt,systemPrompt,imageOrNull,maxTokens,timeoutMs,null);
        }
        public Request(String prompt, String systemPrompt, File imageOrNull, int maxTokens, long timeoutMs, DecisionGrammar controllerGrammar) {
            this.prompt = prompt;
            this.systemPrompt = systemPrompt;
            this.imageOrNull = imageOrNull;
            this.maxTokens = maxTokens;
            this.timeoutMs = timeoutMs;
            this.controllerGrammar = controllerGrammar;
        }
    }

    public interface Listener { void onFinished(Result result); }

    public static final class Result {
        public final String runId, status, rawText;
        public final Integer exitCode;
        public final boolean processExitObserved, inferenceCompleted;
        public final boolean requestCommitted;
        public final String workerGeneration,taskId;
        public final JSONObject nativeReceipt, receipt;
        public final File runDirectory;
        Result(String runId, String status, String rawText, Integer exitCode,
                boolean processExitObserved, boolean inferenceCompleted,
                JSONObject nativeReceipt, JSONObject receipt, File runDirectory) {
            this.runId=runId; this.status=status; this.rawText=rawText; this.exitCode=exitCode;
            this.processExitObserved=processExitObserved; this.inferenceCompleted=inferenceCompleted;
            this.nativeReceipt=nativeReceipt; this.receipt=receipt; this.runDirectory=runDirectory;
            this.requestCommitted=receipt.optBoolean("request_committed",false);
            this.workerGeneration=receipt.optString("worker_generation",null);
            this.taskId=receipt.optString("task_id",null);
        }
    }

    public static final class RunHandle {
        public final String runId;
        private RunHandle(){this(UUID.randomUUID().toString().replace("-", ""));}
        private RunHandle(String runId){this(runId,null);}
        private RunHandle(String runId,RunHandle taskOwner){this.runId=runId;this.taskOwner=taskOwner;this.cancelTicket=TaskCancellationQueue.Ticket.forRun(this,runId);}
        private final RunHandle taskOwner;
        private final TaskCancellationQueue.Ticket cancelTicket;
        private final AtomicBoolean cancelRequested = new AtomicBoolean(false);
        // A caller may be Stop, a deadline, or lifecycle shutdown. Internal failure cleanup is separate.
        private final AtomicBoolean callerCancellationRequested = new AtomicBoolean(false);
        private final AtomicReference<Process> child = new AtomicReference<>();
        private volatile OwnedWorkerCancellation ownedCancellation;
        private void requestCancellationOnly(){callerCancellationRequested.set(true);cancelRequested.set(true);if(taskOwner!=null)taskOwner.requestCancellationOnly();}
        private void markCallerCancellation(){callerCancellationRequested.set(true);if(taskOwner!=null)taskOwner.markCallerCancellation();}
        public void cancel() {markCallerCancellation();cancelForFailure();}
        private void cancelForFailure() {
            cancelRequested.set(true);
            if(taskOwner!=null){taskOwner.cancelForFailure();return;}
            OwnedWorkerCancellation owned=ownedCancellation;
            if(owned!=null){owned.cancel();return;}
            Process p = child.get();
            if (p != null && p.isAlive()) p.destroy();
        }
        public boolean isCancellationRequested() { return cancelRequested.get()||(taskOwner!=null&&taskOwner.isCancellationRequested()); }
        private boolean callerCancellationRequested(){return callerCancellationRequested.get()||(taskOwner!=null&&taskOwner.callerCancellationRequested());}
    }

    /** Retains the existing process-wide slot until the task worker really exits. */
    public final class WarmTask {
        public final String taskId;
        private final RunHandle owner=new RunHandle();
        private final OwnedWorkerCancellation cancellation;
        private final AtomicReference<RunHandle> request=new AtomicReference<>();
        private final AtomicBoolean ending=new AtomicBoolean();
        private volatile WarmProcessSession session;
        private volatile LocalInference.TaskCleanup cleanup;
        private volatile WarmSdkFailure failedSdk;
        private final String scopeToken=UUID.randomUUID().toString().replace("-","");
        private volatile OwnedGenerationScope generationScope;
        private Future<LocalInference.TaskCleanup> finisher;
        private long finisherSubmittedNanos,finisherDeadlineNanos;
        private int acceptedRequests;
        private WarmTask(String taskId){
            this.taskId=taskId;
            cancellation="npu".equals(configuration.compute)
                    ?OwnedWorkerCancellation.forWarmNpu(owner.runId,taskId)
                    :new OwnedWorkerCancellation(owner.runId,taskId);
            owner.ownedCancellation=cancellation; // Fixed before either task or Process can be published.
        }
        public String generation(){return owner.runId;}
        private File directory()throws IOException{return new File(new File(files,"runs"),generation()).getCanonicalFile();}
    }
    public synchronized WarmTask beginWarmTask(String taskId){
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        if(!WarmProcessSession.validId(taskId)||closed.get())throw new IllegalStateException("invalid or closed task model session");
        configuration();
        WarmTask task=new WarmTask(taskId);
        claimProcess(task.owner,active);warmActive.set(task);
        if(closed.get())task.owner.cancel();
        return task;
    }
    public void cancelWarmTask(WarmTask task){
        if(task==null||warmActive.get()!=task)return;
        task.owner.cancel();WarmProcessSession session=task.session;if(session!=null)session.cancel();
    }
    public RunHandle startWarmRequest(final WarmTask task,final Request request,final Listener listener){
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        if(request==null||listener==null)throw new IllegalArgumentException("request and listener required");
        if(task==null||warmActive.get()!=task||task.ending.get()||task.owner.isCancellationRequested()
                ||PROCESS_ACTIVE.get()!=task.owner||closed.get())throw new IllegalStateException("task worker unavailable or retired");
        final RunHandle handle=new RunHandle(UUID.randomUUID().toString().replace("-",""),task.owner);
        if(!task.request.compareAndSet(null,handle))throw new IllegalStateException("overlapping task model request");
        try{executor.execute(()->execute(handle,request,listener,task));}
        catch(RuntimeException error){task.request.compareAndSet(handle,null);throw error;}
        return handle;
    }
    public LocalInference.TaskCleanup finishWarmTask(final WarmTask task){
        if(task.cleanup!=null)return task.cleanup;
        if(warmActive.get()!=task)throw new IllegalStateException("foreign task worker");
        task.ending.set(true);
        try{
            Future<LocalInference.TaskCleanup> finishing;
            synchronized(task){
                if(task.finisher==null){
                    if(task.finisherSubmittedNanos!=0)throw new IllegalStateException("finisher submission already attempted");
                    task.finisherSubmittedNanos=System.nanoTime();
                    task.finisherDeadlineNanos=Math.addExact(task.finisherSubmittedNanos,
                            TimeUnit.MILLISECONDS.toNanos(task.cancellation.finishFutureMillis()));
                    task.finisher=executor.submit(()->finishWarmOwned(task));
                }
                finishing=task.finisher;
            }
            return finishing.get(Math.max(0,task.finisherDeadlineNanos-System.nanoTime()),TimeUnit.NANOSECONDS);
        }
        catch(Exception failure){
            if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
            cancelWarmTask(task);
            return new LocalInference.TaskCleanup(false,task.owner.child.get()!=null,false,null,task.generation(),task.taskId,false,null);
        }
    }
    private LocalInference.TaskCleanup finishWarmOwned(WarmTask task){
        if(task.cleanup!=null)return task.cleanup;
        Process process=task.owner.child.get();boolean observed=false,force=false,valid=false,persisted=false;
        Integer exit=null;String receiptHash=null;JSONObject nativeClose=new JSONObject();boolean cancelledSdkCleanup=false;
        JSONObject receipt=new JSONObject();byte[] nativeCloseBytes=new byte[0];boolean sdkExceptionCleanup=false;
        OwnedGenerationScope.Cleanup generationCleanup=null;boolean generationKnown=false,parentForce=false;
        try{
            if(task.session!=null){WarmProcessSession.Cleanup result=task.session.finish();observed=result.exitObserved;exit=result.exitCode;force=result.forceSent;}
            else if(process!=null){
                task.cancellation.attach(process,task.generation(),task.taskId);
                OwnedWorkerCancellation.Exit stopped=task.cancellation.awaitCancellation();
                observed=stopped.observed;exit=stopped.code;force=stopped.forceSent;
            }
            parentForce=force;
            if(process==null)generationKnown=true;
            else if(observed&&task.generationScope!=null&&warmActive.get()==task
                    &&active.get()==task.owner&&PROCESS_ACTIVE.get()==task.owner&&task.owner.child.get()==process){
                OwnedGenerationScope scope=task.generationScope;
                generationCleanup=scope.finish(true,task.finisherSubmittedNanos,task.finisherDeadlineNanos);
                generationKnown=generationCleanup.known&&task.generationScope==scope&&warmActive.get()==task
                        &&active.get()==task.owner&&PROCESS_ACTIVE.get()==task.owner&&task.owner.child.get()==process;
                force|=generationCleanup.forceKnown&&generationCleanup.forceUsed;
            }
            privateDirectory(files.getCanonicalFile());privateDirectory(new File(files,"runs"));
            File directory=task.directory();privateDirectory(directory);
            File nativeFile=new File(directory,"native-session-result.json");
            if(nativeFile.isFile()){nativeCloseBytes=MobiMindPrivateFiles.read(nativeFile,OUTPUT_LIMIT,true).bytes;
                nativeClose=new JSONObject(new String(nativeCloseBytes,StandardCharsets.UTF_8));}
            valid=process==null||(observed&&exit!=null&&exit==0&&task.session!=null
                    &&"hepta.geniex-task-session.result.v1".equals(nativeClose.optString("schema"))
                    &&task.generation().equals(nativeClose.optString("worker_generation"))&&task.taskId.equals(nativeClose.optString("task_id"))
                    &&task.session.workerPid()==nativeClose.optLong("pid",-1)
                    &&!nativeClose.optBoolean("process_exit_observed",true)
                    &&task.session.requestsSent()==nativeClose.optInt("requests_received",-1)
                    &&task.acceptedRequests==nativeClose.optInt("requests_completed",-1)
                    &&nativeClose.optInt("model_hash_count",-1)==1&&nativeClose.optInt("model_create_count",-1)==1
                    &&nativeClose.optInt("sdk_init_count",-1)==1
                    &&nativeClose.optInt("model_reset_count",-1)==task.session.requestsSent()
                    &&nativeClose.optBoolean("model_metadata_unchanged_before_close",false)&&nativeClose.optBoolean("close_requested",false)
                    &&nativeClose.optInt("signal_observed",-1)==0&&nativeClose.optInt("last_request_status",-1)==0
                    &&nativeClose.optBoolean("sdk_destroy_attempted",false)&&nativeClose.optInt("sdk_destroy_rc",-1)==0
                    &&nativeClose.optBoolean("sdk_deinit_attempted",false)&&nativeClose.optInt("sdk_deinit_rc",-1)==0);
            cancelledSdkCleanup=task.session!=null&&cancelledSdkCleanupBound(nativeClose,task.generation(),task.taskId,
                    task.session.workerPid(),task.session.requestsSent(),task.acceptedRequests,
                    task.owner.isCancellationRequested(),observed,exit,force,android.system.OsConstants.EPIPE);
            // The original 143 SDK predicate is retained; whole-generation
            // absence and zero descendant force are an additional conjunction.
            cancelledSdkCleanup=cancelledSdkCleanup&&generationKnown
                    &&generationCleanup!=null&&generationCleanup.unforced();
            sdkExceptionCleanup=sdkFailureCleanupBound(task,process,nativeCloseBytes,observed,exit,force,receipt);
            put(receipt,"caller_cancellation_requested",task.owner.callerCancellationRequested());
            put(receipt,"sdk_exception_failure_cleanup_binding_valid",sdkExceptionCleanup);
            put(receipt,"sdk_exception_failure",sdkExceptionCleanup?task.failedSdk.proof.audit():JSONObject.NULL);
            put(receipt,"schema","hepta.local-model.task-session.v1");put(receipt,"worker_generation",task.generation());put(receipt,"task_id",task.taskId);
            put(receipt,"app_uid",android.os.Process.myUid());put(receipt,"app_pid",android.os.Process.myPid());
            put(receipt,"process_started",process!=null);put(receipt,"process_exit_observed",observed);
            put(receipt,"exit_code",exit==null?JSONObject.NULL:exit);put(receipt,"force_destroy_sent",force);
            put(receipt,"requests_sent",task.session==null?0:task.session.requestsSent());put(receipt,"requests_accepted",task.acceptedRequests);
            put(receipt,"cleanup_known",process==null||observed&&generationKnown);put(receipt,"native_session_binding_valid",valid);
            put(receipt,"parent_force_destroy_sent",parentForce);
            put(receipt,"finisher_submitted_monotonic_ns",task.finisherSubmittedNanos);
            put(receipt,"finisher_deadline_monotonic_ns",task.finisherDeadlineNanos);
            put(receipt,"generation_cleanup_known",generationKnown);
            put(receipt,"generation_unforced",process==null||generationCleanup!=null&&generationCleanup.unforced());
            put(receipt,"worker_generation_cleanup",generationCleanup==null?JSONObject.NULL:generationCleanup.evidence);
            put(receipt,"native_session_receipt",nativeClose);put(receipt,"cancel_requested",task.owner.isCancellationRequested());
            put(receipt,"cancellation_sdk_cleanup_binding_valid",cancelledSdkCleanup);
            put(receipt,"cleanup_classification",process==null?"not_started":!observed?"exit_unobserved":
                    !generationKnown?"generation_cleanup_unknown":
                    generationCleanup!=null&&generationCleanup.forceUsed?"generation_force_recovery":
                    cancelledSdkCleanup?"expected_cancelled_exit_143_with_observed_sdk_cleanup":
                    sdkExceptionCleanup?"sdk_cpp_exception_exit_70_with_observed_sdk_cleanup":
                    valid?"normal_close_with_observed_sdk_cleanup":
                    exit!=null&&exit==143?"cancelled_exit_143_sdk_cleanup_unverified":
                    force&&exit!=null&&exit==137?"forced_exit_137":"other_exit_sdk_cleanup_unverified");
            put(receipt,"automatic_restart",false);put(receipt,"cross_task_reuse",false);
            recordCancellation(receipt,task.cancellation);
            File appReceipt=new File(directory,"app-session-receipt.json");
            MobiMindPrivateFiles.writeNew(appReceipt,receipt.toString(2).getBytes(StandardCharsets.UTF_8));
            receiptHash=sha256(MobiMindPrivateFiles.read(appReceipt,OUTPUT_LIMIT,true).bytes);persisted=true;
        }catch(Exception error){put(receipt,"close_error",error.toString());}
        boolean cleanup=persisted&&(process==null||observed&&generationKnown);
        LocalInference.TaskCleanup result=new LocalInference.TaskCleanup(cleanup,process!=null,observed,exit,task.generation(),task.taskId,valid,receiptHash);
        if(cleanup){task.owner.child.set(null);active.compareAndSet(task.owner,null);PROCESS_ACTIVE.compareAndSet(task.owner,null);warmActive.compareAndSet(task,null);}
        task.cleanup=result;return result;
    }


    /** Kept only after the failed request's own app receipt has been durably read back. */
    private static final class WarmSdkFailure {
        final Process process;
        final SdkExceptionFailure proof;
        final String appReceiptHash;
        WarmSdkFailure(Process process,SdkExceptionFailure proof,String appReceiptHash){
            this.process=process;this.proof=proof;this.appReceiptHash=appReceiptHash;
        }
    }
    private boolean currentSdkFailureOwner(WarmTask task,RunHandle h,Process process){
        if(task==null||h==null||process==null||warmActive.get()!=task||PROCESS_ACTIVE.get()!=task.owner
                ||active.get()!=task.owner||task.request.get()!=h||h.taskOwner!=task.owner
                ||task.owner.child.get()!=process||h.child.get()!=process||process.isAlive()||task.session==null)return false;
        OwnedWorkerCancellation.Snapshot stopped=task.cancellation.snapshot();
        Integer sessionExit=task.session.observedExitCode();
        return stopped.processBound&&stopped.exitObserved&&stopped.exitCode!=null&&stopped.exitCode.intValue()==70
                &&stopped.forceAttempts==0&&sessionExit!=null&&sessionExit.intValue()==70;
    }
    private SdkExceptionFailure readSdkFailure(WarmTask task,RunHandle h,Request request,Process process,File run,
            byte[] nativeRequest,boolean observed,Integer exit,boolean force)throws Exception{
        if(!currentSdkFailureOwner(task,h,process))throw new IOException("failed SDK request is no longer the owned wait70");
        File canonicalFiles=files.getCanonicalFile();
        File sessionDirectory=new File(new File(canonicalFiles,"runs"),task.generation());
        ArrayList<MobiMindPrivateFiles.Read> held=new ArrayList<>();
        MobiMindPrivateFiles.Read session=readSdkInput(new File(sessionDirectory,"native-session-result.json"),OUTPUT_LIMIT,held);
        MobiMindPrivateFiles.Read metadata=readSdkInput(new File(run,"prompt-evidence.json"),OUTPUT_LIMIT,held);
        MobiMindPrivateFiles.Read formatted=readSdkInput(new File(run,"formatted-prompt.txt"),262144,held);
        MobiMindPrivateFiles.Read ids=readSdkInput(new File(run,"formatted-input-ids.le32"),8192*4,held);
        MobiMindPrivateFiles.Read raw=readSdkInput(new File(run,"raw-text.txt"),OUTPUT_LIMIT,held);
        byte[] prompt=request.prompt.getBytes(StandardCharsets.UTF_8);
        byte[] system=request.systemPrompt==null||request.systemPrompt.isEmpty()?null:request.systemPrompt.getBytes(StandardCharsets.UTF_8);
        byte[] grammar=request.controllerGrammar==null?null:request.controllerGrammar.text.getBytes(StandardCharsets.UTF_8);
        if(request.imageOrNull!=null)throw new IOException("text-only failed request required");
        checkSdkOriginal(new File(run,"prompt.txt"),prompt,held);
        checkSdkOriginal(new File(run,"system.txt"),system,held);
        checkSdkOriginal(new File(run,"grammar.gbnf"),grammar,held);
        if(grammar!=null&&!sha256(grammar).equals(request.controllerGrammar.sha256))throw new IOException("original grammar identity differs");
        String modelPath=new File(new File(canonicalFiles,"model"),configuration.profile.fileName).getPath();
        SdkExceptionFailure.Expected expected=new SdkExceptionFailure.Expected(configuration,task.generation(),task.taskId,h.runId,
                task.session.workerPid(),task.session.requestsSent(),task.acceptedRequests,request.maxTokens,
                modelPath,run.getPath(),prompt,system,grammar);
        SdkExceptionFailure proof=SdkExceptionFailure.bind(expected,nativeRequest,session.bytes,metadata.bytes,
                formatted.bytes,ids.bytes,raw.bytes,true,observed,exit,force);
        for(MobiMindPrivateFiles.Read value:held)value.unchangedPath();
        if(!currentSdkFailureOwner(task,h,process))throw new IOException("failed SDK owner changed during readback");
        return proof;
    }
    private static MobiMindPrivateFiles.Read readSdkInput(File path,int maximum,List<MobiMindPrivateFiles.Read> held)throws Exception{
        MobiMindPrivateFiles.Read value=MobiMindPrivateFiles.read(path,maximum,true);held.add(value);return value;
    }
    private static void checkSdkOriginal(File path,byte[] expected,List<MobiMindPrivateFiles.Read> held)throws Exception{
        if(expected==null){if(MobiMindPrivateFiles.exists(path))throw new IOException("unexpected original "+path.getName());return;}
        if(!Arrays.equals(expected,readSdkInput(path,TEXT_LIMIT,held).bytes))throw new IOException("original "+path.getName()+" changed");
    }
    private boolean sdkFailureCleanupBound(WarmTask task,Process process,byte[] nativeClose,boolean observed,Integer exit,boolean force,
            JSONObject receipt){
        WarmSdkFailure saved=task.failedSdk;
        if(saved==null||saved.process!=process||task.session==null||warmActive.get()!=task||active.get()!=task.owner
                ||PROCESS_ACTIVE.get()!=task.owner||task.owner.child.get()!=process||task.request.get()!=null)return false;
        try{
            File runs=new File(files.getCanonicalFile(),"runs"),run=new File(runs,saved.proof.requestId);
            MobiMindPrivateFiles.Read nativeRequest=MobiMindPrivateFiles.read(new File(run,"native-result.json"),OUTPUT_LIMIT,true);
            MobiMindPrivateFiles.Read appRequest=MobiMindPrivateFiles.read(new File(run,"app-receipt.json"),OUTPUT_LIMIT,true);
            MobiMindPrivateFiles.Read session=MobiMindPrivateFiles.read(new File(new File(runs,task.generation()),"native-session-result.json"),OUTPUT_LIMIT,true);
            boolean bound=Arrays.equals(session.bytes,nativeClose)&&saved.appReceiptHash.equals(sha256(appRequest.bytes))
                    &&saved.proof.matches(configuration,task.generation(),task.taskId,task.session.workerPid(),
                        task.session.requestsSent(),task.acceptedRequests,nativeRequest.bytes,session.bytes,observed,exit,force);
            nativeRequest.unchangedPath();appRequest.unchangedPath();session.unchangedPath();
            return bound;
        }catch(Exception unavailable){put(receipt,"sdk_exception_failure_binding_error",unavailable.toString());return false;}
    }

    /** Cancellation cleanup is a separate proof; it never fabricates CLOSE or normal success. */
    private static boolean cancelledSdkCleanupBound(JSONObject n,String generation,String taskId,long pid,int sent,int accepted,
            boolean cancellationRequested,boolean observed,Integer exit,boolean force,int brokenPipeErrno){
        if(!cancellationRequested||!observed||exit==null||exit.intValue()!=143||force||pid<=0
                ||sent<1||sent>64||accepted<0||accepted>sent||brokenPipeErrno<=0)return false;
        if(!"hepta.geniex-task-session.result.v1".equals(n.optString("schema"))
                ||!generation.equals(n.optString("worker_generation"))||!taskId.equals(n.optString("task_id")))return false;
        String[] truths={"model_metadata_unchanged_before_close","sdk_destroy_attempted","sdk_deinit_attempted"};
        for(String key:truths)if(n.opt(key)!=Boolean.TRUE)return false;
        if(n.opt("process_exit_observed")!=Boolean.FALSE||n.opt("close_requested")!=Boolean.FALSE)return false;
        String[] keys={"pid","requests_received","model_hash_count","model_create_count","sdk_init_count","model_reset_count",
                "signal_observed","last_request_status","sdk_destroy_rc","sdk_deinit_rc","control_done_attempts"};
        long[] expected={pid,sent,1,1,1,sent,15,143,0,0,sent};
        for(int i=0;i<keys.length;i++)if(exactReceiptInteger(n,keys[i])!=expected[i])return false;
        long completed=exactReceiptInteger(n,"requests_completed"),requestStatus=exactReceiptInteger(n,"last_request_return_status");
        if(completed<accepted||completed>sent||!(requestStatus==143&&completed==sent-1||requestStatus==0&&completed==sent))return false;
        long delivered=exactReceiptInteger(n,"control_done_delivered"),error=exactReceiptInteger(n,"control_channel_last_errno");
        Object failed=n.opt("control_channel_write_failed");
        return failed==Boolean.FALSE&&error==0&&delivered==sent
                ||failed==Boolean.TRUE&&error==brokenPipeErrno&&delivered==sent-1;
    }
    private static long exactReceiptInteger(JSONObject value,String key){
        Object raw=value.opt(key);
        return raw instanceof Integer||raw instanceof Long?((Number)raw).longValue():Long.MIN_VALUE;
    }

    /** API invocation evidence does not assert delivery, SDK health or successful generation. */
    private static void recordCancellation(JSONObject receipt,OwnedWorkerCancellation cancellation){
        OwnedWorkerCancellation.Snapshot s=cancellation.snapshot();JSONObject evidence=new JSONObject();
        put(evidence,"schema","hepta.owned-worker-cancellation.v1");put(evidence,"worker_generation",s.generation);put(evidence,"task_id",s.taskId);
        put(evidence,"requested",s.requested);put(evidence,"process_bound",s.processBound);put(evidence,"termination_started",s.terminationStarted);
        put(evidence,"cooperative_grace_ms",s.cooperativeGraceMillis);
        put(evidence,"policy",s.policy);put(evidence,"finish_future_ms",s.finishFutureMillis);
        put(evidence,"force_observation_ms",OwnedWorkerCancellation.FORCE_OBSERVATION_MILLIS);
        put(evidence,"term_destroy_attempts",s.termAttempts);put(evidence,"term_destroy_returned",s.termReturned);
        put(evidence,"force_destroy_attempts",s.forceAttempts);put(evidence,"force_destroy_returned",s.forceReturned);
        put(evidence,"signal_error",s.signalError==null?JSONObject.NULL:s.signalError);
        put(evidence,"process_exit_observed",s.exitObserved);put(evidence,"exit_code",s.exitCode==null?JSONObject.NULL:s.exitCode);
        put(evidence,"sdk_cleanup_proven_by_this_object",false);put(receipt,"owned_worker_cancellation",evidence);
    }

    /** Shares the existing single-model slot and visible Stop with a model-only native worker.
     * The caller must durably reserve its own diagnostic session before attaching a child,
     * and may release only after owned exit (or no start) and durable terminal publication.
     */
    public final class ExternalRunLease {
        private final RunHandle handle;private boolean released;
        private ExternalRunLease(RunHandle handle){this.handle=handle;}
        public String requestId(){return handle.runId;}
        public boolean isCancellationRequested(){return handle.isCancellationRequested();}
        public void cancel(){handle.cancel();}
        public synchronized void attach(Process process){
            if(released||process==null||!handle.child.compareAndSet(null,process))throw new IllegalStateException("invalid external child ownership");
            if(handle.isCancellationRequested()&&process.isAlive())process.destroy();
        }
        public synchronized void releaseAfterTerminalPublication(boolean cleanupKnown){
            if(!cleanupKnown)return;
            Process process=handle.child.get();if(process!=null&&process.isAlive())throw new IllegalStateException("external child still alive");
            if(released)return;released=true;handle.child.set(null);
            active.compareAndSet(handle,null);PROCESS_ACTIVE.compareAndSet(handle,null);
        }
    }
    public ExternalRunLease reserveExternal(String requestId){
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper())throw new IllegalStateException("external reservation must run on main thread");
        if(closed.get()||requestId==null||!requestId.matches("[0-9a-f]{32}"))throw new IllegalStateException("invalid external reservation");
        RunHandle handle=new RunHandle(requestId);
        claimProcess(handle,active);return new ExternalRunLease(handle);
    }


    /** An aggregate startup barrier has no child attachment API and is never an external lease. */
    public final class RecoveryBarrier {
        private final LocalModelEngine owner=LocalModelEngine.this;
        private final RunHandle handle;
        private final RecoverySlotHandoff<RunHandle> handoff;
        private RecoveryBarrier(RunHandle handle,RecoverySlotHandoff<RunHandle> handoff){
            this.handle=handle;this.handoff=handoff;
        }
    }
    private static RecoverySlotHandoff.Slot<RunHandle> recoverySlot(final AtomicReference<RunHandle> value){
        return new RecoverySlotHandoff.Slot<RunHandle>(){
            @Override public RunHandle get(){return value.get();}
            @Override public boolean compareAndSet(RunHandle expected,RunHandle replacement){
                return value.compareAndSet(expected,replacement);
            }
        };
    }
    private void recoveryMainThread(){
        if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper())
            throw new IllegalStateException("recovery ownership changes must run on main thread");
    }
    public RecoveryBarrier reserveRecoveryBarrier(){
        recoveryMainThread();
        if(closed.get())throw new IllegalStateException("engine is closed");
        RunHandle handle=new RunHandle();
        final RecoverySlotHandoff<RunHandle> handoff;
        synchronized(PROCESS_ADMISSION){
            if(ACTIVE_CANCELLATION.pending())throw new IllegalStateException("prior captured cancellation worker still active");
            handoff=RecoverySlotHandoff.acquire(recoverySlot(PROCESS_ACTIVE),recoverySlot(active),handle);
        }
        RecoveryBarrier barrier=new RecoveryBarrier(handle,handoff);
        if(closed.get())throw new IllegalStateException("engine closed while retaining recovery barrier");
        return barrier;
    }
    public boolean canReserveRecovery(RecoveryBarrier barrier){
        recoveryMainThread();
        return !ACTIVE_CANCELLATION.pending()&&!LocalProbeApplication.permissionPreparationBlocks(context)&&!closed.get()&&barrier!=null&&barrier.owner==this
                &&barrier.handle.child.get()==null&&barrier.handoff.canBorrow();
    }
    interface RecoveryCloseListener { void onClosed(RecoveryReservation reservation); }
    /** Fresh cancellation state per explicit confirmation; failure restores the same occupied barrier. */
    public final class RecoveryReservation implements RecoveryDispatch.Lease {
        private final RecoveryBarrier barrier;
        private final RunHandle handle;
        private final RecoverySlotHandoff<RunHandle>.Attempt attempt;
        private final AtomicBoolean released=new AtomicBoolean(false);
        private final AtomicBoolean closeFinished=new AtomicBoolean(false);
        private volatile RecoveryCloseListener closeListener;
        private RecoveryReservation(RecoveryBarrier barrier,RunHandle handle,
                RecoverySlotHandoff<RunHandle>.Attempt attempt){
            this.barrier=barrier;this.handle=handle;this.attempt=attempt;
        }
        public String transactionId(){return handle.runId;}
        boolean belongsTo(RecoveryBarrier expected){
            return expected!=null&&barrier==expected&&barrier.owner==LocalModelEngine.this;
        }
        boolean isCloseFinished(){return closeFinished.get();}
        boolean wasReleased(){return closeFinished.get()&&attempt.wasReleased();}
        void setCloseListener(RecoveryCloseListener listener){
            recoveryMainThread();
            if(listener==null||closeListener!=null||released.get())
                throw new IllegalStateException("recovery close listener already fixed");
            closeListener=listener;
        }
        public boolean isCancellationRequested(){
            return closed.get()||released.get()||handle.isCancellationRequested()||!attempt.isOwned();
        }
        void requireOwnedBy(RecoveryBarrier expected){
            if(expected==null||barrier!=expected||barrier.owner!=LocalModelEngine.this
                    ||isCancellationRequested()||handle.child.get()!=null)
                throw new IllegalStateException("recovery reservation is cancelled or has different ownership");
            attempt.requireOwned();
        }
        void commit(RecoveryBarrier expected){
            recoveryMainThread();requireOwnedBy(expected);attempt.commit();
        }
        @Override public void close(){
            if(!released.compareAndSet(false,true))return;
            try{
                synchronized(PROCESS_ADMISSION){
                    if(handle.child.get()!=null)
                        throw new IllegalStateException("recovery reservation unexpectedly owns a child");
                    if(closed.get()||handle.isCancellationRequested())attempt.retainBarrierOnClose();
                    attempt.close();
                }
            }finally{
                closeFinished.set(true);
                RecoveryCloseListener listener=closeListener;
                if(listener!=null){
                    try{listener.onClosed(this);}
                    catch(RuntimeException ignored){
                        // The Application still owns its references and can reconcile this receipt
                        // on its next main-thread entry; notification is never a release authority.
                    }
                }
            }
        }
    }
    public RecoveryReservation reserveRecovery(RecoveryBarrier barrier){
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        recoveryMainThread();
        if(closed.get()||barrier==null||barrier.owner!=this||barrier.handle.child.get()!=null)
            throw new IllegalStateException("owned recovery barrier is unavailable");
        RunHandle handle=new RunHandle();
        final RecoveryReservation reservation;
        synchronized(PROCESS_ADMISSION){
            if(ACTIVE_CANCELLATION.pending())throw new IllegalStateException("prior captured cancellation worker still active");
            reservation=new RecoveryReservation(barrier,handle,barrier.handoff.borrow(handle));
        }
        if(closed.get()){reservation.close();throw new IllegalStateException("engine closed during recovery handoff");}
        return reservation;
    }

    public RunHandle start(final Request request, final Listener listener) {
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        if (request == null || listener == null) throw new IllegalArgumentException("request and listener required");
        if (closed.get()) throw new IllegalStateException("engine is closed");
        final RunHandle handle = new RunHandle();
        claimProcess(handle,active);
        try {
            executor.execute(() -> execute(handle, request, listener));
        } catch (RuntimeException e) {
            active.compareAndSet(handle, null);
            PROCESS_ACTIVE.compareAndSet(handle, null);
            throw e;
        }
        return handle;
    }

    private static void claimProcess(RunHandle handle,AtomicReference<RunHandle> local){
        synchronized(PROCESS_ADMISSION){
            if(ACTIVE_CANCELLATION.pending()||!PROCESS_ACTIVE.compareAndSet(null,handle))
                throw new IllegalStateException("local model or captured cancellation still owns the process slot");
            local.set(handle);
        }
    }
    public boolean isBusy() { return PROCESS_ACTIVE.get() != null||ACTIVE_CANCELLATION.pending()||LocalProbeApplication.permissionPreparationBlocks(context); }
    public Result lastResult() { return lastResult; }
    /** Captures once under the same gate as all process admissions. Return is a request, never exit proof. */
    public void cancelActive() {
        synchronized(PROCESS_ADMISSION){
            final RunHandle captured=active.get();
            if(captured==null||PROCESS_ACTIVE.get()!=captured)return;
            captured.requestCancellationOnly();lastCancellation=captured.cancelTicket;
            ACTIVE_CANCELLATION.request(captured.cancelTicket,new TaskCancellationQueue.Lease(){public boolean current(String runId){
                return captured.runId.equals(runId)&&active.get()==captured&&PROCESS_ACTIVE.get()==captured;
            }},new Runnable(){public void run(){captured.cancel();}});
        }
    }
    JSONObject cancellationEvidence(){TaskCancellationQueue.Ticket value=lastCancellation;return value==null?null:new JSONObject(value.evidence());}
    public File modelDirectory() { return new File(files, "model"); }
    public File modelFile() { return new File(modelDirectory(), configuration.profile.fileName); }
    public LocalRuntimeConfig configuration() {
        if (configurationError != null) throw new IllegalStateException("本地运行参数无效：" + configurationError);
        return configuration;
    }
    private LocalRuntimeConfig readConfiguration() throws Exception {
        File dir = modelDirectory().getCanonicalFile();
        File file = new File(dir, "runtime-config.json");
        if (!file.exists()) return LocalRuntimeConfig.defaults();
        if (!dir.getParentFile().equals(files.getCanonicalFile()) || !file.getCanonicalFile().equals(file))
            throw new IOException("runtime-config must remain in app-private files/model");
        android.system.StructStat st = Os.lstat(file.getPath());
        if (!android.system.OsConstants.S_ISREG(st.st_mode) || st.st_uid != android.os.Process.myUid()
                || st.st_nlink != 1 || (st.st_mode & 0777) != 0600)
            throw new IOException("runtime-config must be a single app-owned regular mode0600 file");
        JSONObject value = new JSONObject(new String(readBounded(file, 4096), StandardCharsets.UTF_8));
        Map<String,Object> fields=new java.util.HashMap<>();
        Iterator<String> names=value.keys();while(names.hasNext()){String key=names.next();fields.put(key,value.get(key));}
        return LocalRuntimeConfig.fromFields(fields);
    }
    public long availableMemoryBytes() {
        ActivityManager.MemoryInfo info = memoryInfo();
        return MemoryAvailability.read(info.availMem,info.totalMem,info.lowMemory).availableBytes;
    }
    private ActivityManager.MemoryInfo memoryInfo() {
        ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
        ((ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE)).getMemoryInfo(info);
        return info;
    }

    private void execute(RunHandle h, Request r, Listener listener) { execute(h,r,listener,null); }

    private void execute(RunHandle h, Request r, Listener listener, WarmTask task) {
        long start = SystemClock.elapsedRealtime();
        File run = new File(new File(files, "runs"), h.runId);
        JSONObject receipt = new JSONObject(), nativeResult = new JSONObject();
        String raw = "", status = "preflight_failed", error = null;
        byte[] rawBytes=new byte[0];
        Integer exit = null;
        boolean observed = false, complete = false, timedOut = false, forceSent = false;
        Process process = task==null?null:task.owner.child.get();
        WarmProcessSession.Reply warmReply=null;
        SdkExceptionFailure failedSdkProof=null;
        try {
            privateDirectory(files.getCanonicalFile());
            privateDirectory(new File(files, "runs").getCanonicalFile());
            privateDirectory(run = run.getCanonicalFile());
            put(receipt, "schema", task==null?"hepta.local-model.receipt.v2":"hepta.local-model.task-request.v1");
            if(task!=null){put(receipt,"worker_generation",task.generation());put(receipt,"task_id",task.taskId);}
            put(receipt, "run_id", h.runId);
            put(receipt, "app_uid", android.os.Process.myUid());
            put(receipt, "app_pid", android.os.Process.myPid());
            put(receipt, "parent_death_guard_requested", true);
            put(receipt, "expected_parent_pid", android.os.Process.myPid());
            put(receipt, "parent_death_guard_is_cleanup_proof", false);
            put(receipt, "package_name", context.getPackageName());
            LocalRuntimeConfig config = configuration();
            put(receipt, "runtime", LocalRuntimeConfig.RUNTIME);
            put(receipt, "mode", LocalRuntimeConfig.MODE);
            put(receipt, "model_id", config.profile.repository);
            put(receipt, "model_profile", config.profile.id);
            put(receipt, "model_revision", config.profile.revision);
            put(receipt, "compute_requested", config.compute);
            put(receipt, "context_tokens", config.contextTokens);
            put(receipt, "fallback_allowed", false);
            put(receipt, "image_sent_to_model", false);
            put(receipt, "hardware_execution_independently_verified", false);
            put(receipt, "sdk_version_expected", "0.10.0");
            put(receipt, "production_agent_ready", false);
            put(receipt, "phone_actions_supported_by_engine", false);
            put(receipt, "automatic_retry", false);
            put(receipt, "started_wall_ms", System.currentTimeMillis());
            put(receipt, "minimum_available_memory_bytes", config.profile.minimumAvailableBytes);
            validateText(r.prompt, true);
            validateText(r.systemPrompt, false);
            if (r.imageOrNull != null) throw new IOException("selected text profile cannot contain an image");
            if (r.maxTokens < 1 || r.maxTokens > 1024) throw new IOException("maxTokens must be 1..1024");
            if (r.timeoutMs < 1000 || r.timeoutMs > 300000) throw new IOException("timeoutMs must be 1000..300000");
            ActivityManager.MemoryInfo memory = memoryInfo();
            MemoryAvailability admission=MemoryAvailability.read(memory.availMem,memory.totalMem,memory.lowMemory);
            recordMemory(receipt,admission,"before");
            put(receipt, "total_memory_bytes", memory.totalMem);
            put(receipt, "android_low_memory", memory.lowMemory);
            boolean retained=task!=null&&task.session!=null;
            put(receipt,"model_memory_already_reserved",retained);
            put(receipt,"memory_admission_scope",retained?"existing_owned_instance_no_second_weight_reservation":"new_model_instance");
            if (!admission.admits(retained?0:config.profile.minimumAvailableBytes)) {
                status = "insufficient_memory";
                throw new IOException("selected model refused: available physical RAM below profile threshold, invalid measurement, or Android lowMemory=true; source="+admission.source);
            }
            File model = modelDirectory().getCanonicalFile();
            if (!model.getParentFile().equals(files.getCanonicalFile()) || !model.isDirectory())
                throw new IOException("model must be imported into app private files/model");
            File selectedModel = modelFile().getCanonicalFile();
            if (!selectedModel.getParentFile().equals(model) || !selectedModel.getName().equals(config.profile.fileName))
                throw new IOException("only the selected pinned app-private GGUF is accepted");
            if (h.isCancellationRequested()) { status = "cancelled_before_start"; throw new IOException("cancel requested before model verification"); }
            modelVerifier.verify(selectedModel,config.profile, () -> h.isCancellationRequested());
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File runner = new File(nativeDir, "libhepta_local_runner.so").getCanonicalFile();
            if (!runner.getParentFile().equals(nativeDir) || !runner.isFile() || !runner.canExecute())
                throw new IOException("installed nativeLibraryDir runner unavailable");
            if (!new File(nativeDir, "libgeniex_plugin_llama_cpp.so").isFile()) throw new IOException("llama_cpp plugin not installed");
            put(receipt, "model_directory", model.getPath());
            put(receipt, "model_path", selectedModel.getPath());
            put(receipt, "model_sha256_verified", config.profile.sha256);
            put(receipt, "native_library_directory", nativeDir.getPath());
            put(receipt, "runner_path", runner.getPath());
            File prompt = new File(run, "prompt.txt"), system = new File(run, "system.txt");
            writePrivate(prompt, r.prompt.getBytes(StandardCharsets.UTF_8));
            if (r.systemPrompt != null && !r.systemPrompt.isEmpty()) writePrivate(system, r.systemPrompt.getBytes(StandardCharsets.UTF_8));
            File grammar=null;
            if(r.controllerGrammar!=null){
                grammar=new File(run,"grammar.gbnf");
                writePrivate(grammar,r.controllerGrammar.text.getBytes(StandardCharsets.UTF_8));
                put(receipt,"grammar_schema",r.controllerGrammar.schema);
                put(receipt,"grammar_sha256",r.controllerGrammar.sha256);
                put(receipt,"grammar_observation_id",r.controllerGrammar.observationId);
                put(receipt,"grammar_current_package",r.controllerGrammar.currentPackage);
                put(receipt,"grammar_file",grammar.getPath());
                ObservedTargetLabels targets=r.controllerGrammar.targets;
                put(receipt,"target_label_contract",new JSONObject().put("schema",ObservedTargetLabels.SCHEMA)
                        .put("encoding",ObservedTargetLabels.ENCODING).put("observation_id",targets.observationId)
                        .put("package",targets.packageName).put("sha256",targets.sha256).put("pairs_count",targets.labels.size()));
                ObservedAppLabels apps=r.controllerGrammar.appLabels;
                if(apps!=null)put(receipt,"app_label_contract",new JSONObject().put("schema",ObservedAppLabels.SCHEMA)
                        .put("encoding",ObservedAppLabels.ENCODING).put("observation_id",apps.observationId)
                        .put("package",apps.currentPackage).put("sha256",apps.sha256).put("pairs_count",apps.labels.size()));
            }
            File resultFile = new File(run, "native-result.json"), rawFile = new File(run, "raw-text.txt");
            File logDirectory=task==null?run:task.directory();privateDirectory(logDirectory);
            File stdout = new File(logDirectory, "stdout.log"), stderr = new File(logDirectory, "stderr.log");
            if(task==null||task.session==null){writePrivate(stdout, new byte[0]); writePrivate(stderr, new byte[0]);}
            List<String> args = new ArrayList<>(Arrays.asList(runner.getPath(),
                "--expected-parent-pid", Integer.toString(android.os.Process.myPid()),
                "--model-profile", config.profile.id,
                "--request-id", h.runId, "--mode", LocalRuntimeConfig.MODE, "--runtime", LocalRuntimeConfig.RUNTIME, "--compute", config.compute,
                "--model", selectedModel.getPath(), "--prompt-file", prompt.getPath(),
                "--result-file", resultFile.getPath(), "--text-file", rawFile.getPath(),
                "--ctx-size", Integer.toString(config.contextTokens), "--max-tokens", Integer.toString(r.maxTokens),
                "--threads", Integer.toString(config.threads), "--timeout-ms", Long.toString(r.timeoutMs), "--log-level", "debug"));
            if (system.isFile()) { args.add("--system-file"); args.add(system.getPath()); }
            if (grammar != null) { args.add("--grammar-file"); args.add(grammar.getPath()); }
            if(task!=null){args.add("--warm-generation");args.add(task.generation());args.add("--warm-task-id");args.add(task.taskId);
                args.add("--warm-session-dir");args.add(task.directory().getPath());}
            put(receipt, "argv", task==null||task.session==null?new JSONArray(args):JSONObject.NULL);
            put(receipt,"worker_started_this_request",task==null||task.session==null);
            put(receipt, "prompt_sha256", sha256(r.prompt.getBytes(StandardCharsets.UTF_8)));
            put(receipt, "grammar_constraint_enabled", r.controllerGrammar != null);
            put(receipt, "stdout_file", stdout.getPath()); put(receipt, "stderr_file", stderr.getPath());
            if (h.isCancellationRequested()) { status = "cancelled_before_start"; throw new IOException("cancel requested before start"); }
            if(task!=null&&task.session==null){
                if(task.generationScope!=null)throw new IOException("generation scope already prepared");
                task.generationScope=new OwnedGenerationScope(files,runner,task.generation(),task.taskId,task.scopeToken);
            }
            ProcessBuilder builder = new ProcessBuilder(args);
            builder.directory(run);
            if(task==null)builder.redirectOutput(stdout);
            builder.redirectError(stderr);
            Map<String, String> env = builder.environment();
            if(task!=null){
                if(task.generationScope==null)throw new IOException("generation scope unavailable before worker start");
                task.generationScope.initialEnvironment(env);
            }
            env.put("LD_LIBRARY_PATH", nativeDir.getPath() + ":/vendor/lib64");
            env.put("ADSP_LIBRARY_PATH", nativeDir.getPath() + ";/vendor/lib/rfsa/adsp;/system/lib/rfsa/adsp;/dsp");
            env.put("HEPTA_LOCAL_NATIVE_LIB_DIR", nativeDir.getPath());
            env.remove("GENIEX_QAIRT_LIB");
            // llama_cpp resolves its backend/DSP libraries from this directory.
            // The native adapter registers the renamed plugin explicitly.
            env.put("GENIEX_PLUGIN_PATH", nativeDir.getPath());
            if ("gpu".equals(config.compute)) {
                File cacheRoot = context.getCacheDir();
                if (cacheRoot == null) throw new IOException("app cache directory unavailable");
                cacheRoot = cacheRoot.getCanonicalFile();
                File kernelCache = new File(cacheRoot, "hepta-opencl-kernels");
                if (!cacheRoot.equals(kernelCache.getCanonicalFile().getParentFile()))
                    throw new IOException("OpenCL kernel cache must stay inside app cache");
                MobiMindPrivateFiles.directory(kernelCache, false);
                if (!kernelCache.equals(kernelCache.getCanonicalFile()))
                    throw new IOException("OpenCL kernel cache path changed");
                env.put("GGML_OPENCL_KERNEL_CACHE_DIR", kernelCache.getPath());
                put(receipt, "opencl_kernel_cache_directory", kernelCache.getPath());
            }
            if(task!=null){
                if(task.session==null){
                    process=builder.start();task.owner.child.set(process);
                    task.cancellation.attach(process,task.generation(),task.taskId);
                    task.session=new WarmProcessSession(process,task.generation(),task.taskId,task.cancellation);
                }else process=task.owner.child.get();
                h.child.set(process);
                if(h.isCancellationRequested()||task.ending.get())task.session.cancel();
                warmReply=task.session.exchange(h.runId,r.maxTokens,r.timeoutMs);
                put(receipt,"request_sequence",warmReply.sequence);
                put(receipt,"worker_pid",task.session.workerPid());
                status="request_returned";
            }else{
            process = builder.start(); h.child.set(process);
            put(receipt, "process_started", true);
            status = "running";
            long launched = SystemClock.elapsedRealtime(), terminationAt = 0;
            while (true) {
                if (process.waitFor(200, TimeUnit.MILLISECONDS)) { exit = process.exitValue(); observed = true; break; }
                long now = SystemClock.elapsedRealtime();
                if (now - launched > r.timeoutMs + 2000) timedOut = true;
                if (h.isCancellationRequested() || timedOut) {
                    if (terminationAt == 0) { terminationAt = now; process.destroy(); }
                    if (!forceSent && now - terminationAt >= 2000) { process.destroyForcibly(); forceSent = true; }
                    if (now - terminationAt >= 12000) { status = "termination_unknown"; break; }
                }
            }
            }
            if(rawFile.isFile()){
                rawBytes=task==null?readBounded(rawFile,OUTPUT_LIMIT):MobiMindPrivateFiles.read(rawFile,OUTPUT_LIMIT,true).bytes;
                raw=new String(rawBytes,StandardCharsets.UTF_8);
            }
            if(resultFile.isFile())nativeResult=new JSONObject(new String(task==null?readBounded(resultFile,OUTPUT_LIMIT):
                MobiMindPrivateFiles.read(resultFile,OUTPUT_LIMIT,true).bytes,StandardCharsets.UTF_8));
            // The native deadline precedes the outer watchdog by two seconds.
            // Its owned exit/identity-bound deadline must retain timeout status.
            if (exit != null && exit == 124) timedOut = true;
            if ((task==null?"hepta.geniex-once.result.v1":"hepta.geniex-task-request.result.v1").equals(nativeResult.optString("schema"))
                    && h.runId.equals(nativeResult.optString("request_id"))
                    && LocalRuntimeConfig.RUNTIME.equals(nativeResult.optString("runtime"))
                    && nativeResult.optBoolean("deadline_observed", false)) timedOut = true;
            JSONObject nativeInputs=nativeResult.optJSONObject("input_sha256");
            boolean grammarBinding=nativeInputs!=null&&(r.controllerGrammar==null
                ?nativeInputs.has("grammar")&&nativeInputs.isNull("grammar")
                :r.controllerGrammar.sha256.equals(nativeInputs.optString("grammar")));
            put(receipt,"grammar_binding_valid",grammarBinding);
            boolean binding = (task==null?"hepta.geniex-once.result.v1":"hepta.geniex-task-request.result.v1").equals(nativeResult.optString("schema"))
                && h.runId.equals(nativeResult.optString("request_id"))
                && LocalRuntimeConfig.MODE.equals(nativeResult.optString("mode"))
                && LocalRuntimeConfig.RUNTIME.equals(nativeResult.optString("runtime"))
                && config.compute.equals(nativeResult.optString("compute_requested"))
                && selectedModel.getPath().equals(nativeResult.optString("model_path"))
                && config.profile.id.equals(nativeResult.optString("model_profile"))
                && config.profile.sha256.equals(nativeResult.optString("model_sha256_verified"))
                && config.profile.architecture.equals(nativeResult.optString("model_architecture"))
                && config.profile.bytes==nativeResult.optLong("model_bytes_verified",-1)
                && nativeResult.optBoolean("model_metadata_unchanged",false)
                && nativeResult.has("chat_template_enable_thinking")&&!nativeResult.optBoolean("chat_template_enable_thinking",true)
                && nativeResult.has("automatic_cpu_fallback")&&!nativeResult.optBoolean("automatic_cpu_fallback",true)
                && nativeResult.optInt("n_ctx_create", 0) == config.contextTokens
                && config.matchesResolvedDevice(nativeResult.optString("device_resolved"),
                    !nativeResult.has("device_warning") || !nativeResult.isNull("device_warning"),
                    nativeResult.optInt("n_gpu_layers_create", 0))
                && nativeBudgetValid(nativeResult, config, r.maxTokens)
                && grammarBinding
                && nativeInputs!=null&&sha256(r.prompt.getBytes(StandardCharsets.UTF_8)).equals(nativeInputs.optString("prompt"))
                && (system.isFile()?sha256(r.systemPrompt.getBytes(StandardCharsets.UTF_8)).equals(nativeInputs.optString("system"))
                    :nativeInputs.has("system")&&nativeInputs.isNull("system"))
                && !nativeResult.optBoolean("raw_text_truncated", true)
                && nativeResult.optBoolean("raw_text_utf8", false)
                && rawFile.isFile()
                && sha256(rawBytes).equals(nativeResult.optString("raw_text_sha256"))
                && rawBytes.length == nativeResult.optLong("raw_text_bytes", -1);
            if(task!=null)binding=binding&&warmReply!=null
                &&task.generation().equals(nativeResult.optString("worker_generation"))&&task.taskId.equals(nativeResult.optString("task_id"))
                &&warmReply.sequence==nativeResult.optInt("request_sequence",-1)
                &&task.session.workerPid()==nativeResult.optLong("pid",-1)
                &&nativeResult.optInt("model_hash_count",-1)==1&&nativeResult.optInt("model_create_count",-1)==1
                &&nativeResult.has("model_hash_performed_this_request")
                &&nativeResult.optBoolean("model_hash_performed_this_request",false)==(warmReply.sequence==1)
                &&nativeResult.optInt("sdk_init_count",-1)==1&&nativeResult.optInt("model_reset_count",-1)==warmReply.sequence
                &&nativeResult.optInt("model_reset_rc",-1)==0&&nativeResult.optInt("request_status",-1)==0
                &&nativeResult.optBoolean("worker_retained",false)&&!nativeResult.optBoolean("process_exit_observed",true)
                &&nativeResult.has("worker_exit_status_planned")&&nativeResult.isNull("worker_exit_status_planned");
            put(receipt, "native_result_binding_valid", binding);
            put(receipt, "runtime_device_selection_valid", config.matchesResolvedDevice(nativeResult.optString("device_resolved"),
                    !nativeResult.has("device_warning") || !nativeResult.isNull("device_warning"), nativeResult.optInt("n_gpu_layers_create", 0)));
            put(receipt, "device_resolved", nativeResult.opt("device_resolved"));
            put(receipt, "native_context_budget_valid", nativeBudgetValid(nativeResult, config, r.maxTokens));
            complete = (task==null?(observed && exit != null && exit == 0):
                (warmReply!=null&&!task.ending.get()&&process!=null&&process.isAlive())) && binding
                && nativeResult.optBoolean("generation_complete", false)
                && !h.isCancellationRequested() && !timedOut;
            if (task!=null||observed) status = complete ? (task==null?"completed":"request_completed") : h.isCancellationRequested() ? "cancelled" : timedOut ? "timed_out" : "native_failed";
            if (!complete && error == null) error = nativeResult.optString("error", "native inference did not complete");
        } catch (Throwable e) {
            if(e instanceof WarmProcessSession.Failure){WarmProcessSession.Failure failure=(WarmProcessSession.Failure)e;
                timedOut=failure.timedOut;observed=failure.cleanup.exitObserved;exit=failure.cleanup.exitCode;forceSent=failure.cleanup.forceSent;}
            error = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
            if(task!=null&&process!=null){
                task.cancellation.attach(process,task.generation(),task.taskId);
                task.owner.cancelForFailure();
                OwnedWorkerCancellation.Exit stopped=task.cancellation.awaitCancellation();
                observed=stopped.observed;exit=stopped.code;forceSent|=stopped.forceSent;
            }else if (process != null && process.isAlive()) {
                process.destroy();
                try {
                    if (!process.waitFor(2000, TimeUnit.MILLISECONDS)) { process.destroyForcibly(); forceSent = true; }
                    if (process.waitFor(10000, TimeUnit.MILLISECONDS)) { observed = true; exit = process.exitValue(); }
                } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            }
            if (process != null && !observed && !process.isAlive()) { observed = true; exit = process.exitValue(); }
            if (process != null && !observed) status = "termination_unknown";
            else if (process != null) status = h.isCancellationRequested() ? "cancelled" : "engine_failed";
            else if (h.isCancellationRequested()) status = "cancelled_before_start";
            complete = false;
        } finally {
            if(task!=null&&(h.isCancellationRequested()||task.ending.get())){complete=false;status="cancelled";}
            if(task!=null&&!complete&&task.session!=null){
                task.owner.cancelForFailure();WarmProcessSession.Cleanup stopped=task.session.finish();
                observed=stopped.exitObserved;exit=stopped.exitCode;forceSent|=stopped.forceSent;
                if(!observed)status="termination_unknown";
            }
            // exchange throws before its success-only receipt read. Read a failed request only after physical exit.
            if(task!=null&&!complete&&observed&&process!=null&&task.session!=null){
                try{
                    File resultFile=new File(run,"native-result.json");
                    if(MobiMindPrivateFiles.exists(resultFile)){
                        MobiMindPrivateFiles.Read nativeRead=MobiMindPrivateFiles.read(resultFile,OUTPUT_LIMIT,true);
                        nativeResult=new JSONObject(new String(nativeRead.bytes,StandardCharsets.UTF_8));
                        put(receipt,"native_result_binding_valid",false);
                        if(exit!=null&&exit.intValue()==70&&!forceSent&&!timedOut)
                            failedSdkProof=readSdkFailure(task,h,r,process,run,nativeRead.bytes,observed,exit,forceSent);
                        nativeRead.unchangedPath();
                    }
                }catch(Exception unavailable){failedSdkProof=null;put(receipt,"sdk_exception_failure_read_error",unavailable.toString());}
            }
            boolean callerCancellation=h.callerCancellationRequested();
            if(failedSdkProof!=null){
                complete=false;status=callerCancellation?"cancelled":"native_failed";
                error="sdk_cpp_exception ("+failedSdkProof.kind+")";
            }
            put(receipt,"caller_cancellation_requested",callerCancellation);
            put(receipt,"sdk_exception_failure_binding_valid",failedSdkProof!=null);
            try{put(receipt,"sdk_exception_failure",failedSdkProof==null?JSONObject.NULL:failedSdkProof.audit());}
            catch(Exception unavailable){
                failedSdkProof=null;status=h.isCancellationRequested()?"cancelled":"engine_failed";
                put(receipt,"sdk_exception_failure_binding_valid",false);put(receipt,"sdk_exception_failure",JSONObject.NULL);
                put(receipt,"sdk_exception_failure_read_error",unavailable.toString());
            }
            try{
                ActivityManager.MemoryInfo after=memoryInfo();
                recordMemory(receipt,MemoryAvailability.read(after.availMem,after.totalMem,after.lowMemory),"after");
            }catch(Exception unavailable){put(receipt,"memory_after_error",unavailable.getClass().getSimpleName());}
            put(receipt, "status", status);
            put(receipt, "error", error == null ? JSONObject.NULL : error);
            put(receipt, "process_started", process != null);
            put(receipt, "process_exit_observed", observed);
            put(receipt, "exit_code", exit == null ? JSONObject.NULL : exit);
            put(receipt, "inference_completed", complete);
            put(receipt,"request_committed",task!=null&&complete);
            put(receipt, "cancel_requested", h.isCancellationRequested());
            put(receipt, "timeout_observed", timedOut);
            put(receipt, "force_destroy_sent", forceSent);
            if(task!=null)recordCancellation(receipt,task.cancellation);
            put(receipt, "elapsed_ms", SystemClock.elapsedRealtime() - start);
            put(receipt, "native_receipt", nativeResult);
            put(receipt, "raw_text_file", new File(run, "raw-text.txt").getPath());
            put(receipt, "raw_text_sha256_read", failedSdkProof==null?sha256(raw.getBytes(StandardCharsets.UTF_8)):failedSdkProof.rawHash);
            try {
                File appReceipt=new File(run,"app-receipt.json");byte[] bytes=receipt.toString(2).getBytes(StandardCharsets.UTF_8);
                if(task==null)writePrivate(appReceipt,bytes);else MobiMindPrivateFiles.writeNew(appReceipt,bytes);
                if(failedSdkProof!=null){
                    byte[] persisted=MobiMindPrivateFiles.read(appReceipt,OUTPUT_LIMIT,true).bytes;
                    if(!Arrays.equals(bytes,persisted)||!currentSdkFailureOwner(task,h,process))
                        throw new IOException("failed SDK app receipt/owner changed");
                    task.failedSdk=new WarmSdkFailure(process,failedSdkProof,sha256(persisted));
                }
            }
            catch (Exception persistError) {
                put(receipt, "receipt_write_error", persistError.toString());
                if(task!=null){
                    complete=false;status="receipt_failed";put(receipt,"request_committed",false);put(receipt,"inference_completed",false);
                    task.owner.cancelForFailure();
                    if(task.session!=null){WarmProcessSession.Cleanup stopped=task.session.finish();observed=stopped.exitObserved;exit=stopped.exitCode;forceSent|=stopped.forceSent;}
                    if(!observed&&process!=null)status="termination_unknown";
                    put(receipt,"status",status);put(receipt,"process_exit_observed",observed);
                    put(receipt,"exit_code",exit==null?JSONObject.NULL:exit);put(receipt,"force_destroy_sent",forceSent);
                }
            }
            final boolean release = process == null || observed;
            if(task!=null){
                if(complete)task.acceptedRequests++;
                h.child.set(null);task.request.compareAndSet(h,null);
            }
            else if (release) { h.child.set(null); active.compareAndSet(h, null); PROCESS_ACTIVE.compareAndSet(h, null); }
            else {
                final Process stillOwned = process;
                Thread watcher = new Thread(() -> {
                    try { stillOwned.waitFor(); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); return; }
                    h.child.set(null); active.compareAndSet(h, null); PROCESS_ACTIVE.compareAndSet(h, null);
                }, "local-model-owned-process-reaper");
                watcher.setDaemon(true); watcher.start();
            }
            lastResult = new Result(h.runId,status,raw,exit,observed,complete,nativeResult,receipt,run);
            try { listener.onFinished(lastResult); }
            catch (Throwable ignored) { /* A client callback cannot lose native process ownership. */ }
        }
    }

    private static boolean nativeBudgetValid(JSONObject nativeResult, LocalRuntimeConfig config, int generation) {
        JSONObject budget = nativeResult.optJSONObject("prompt_budget");
        if (budget == null) return false;
        Map<String,Object> fields=new java.util.HashMap<>();
        Iterator<String> names=budget.keys();while(names.hasNext()){String key=names.next();fields.put(key,budget.opt(key));}
        JSONObject profile=nativeResult.optJSONObject("profile");
        return NativeBudgetVerifier.valid(fields,config,generation,profile==null?-1:profile.optLong("prompt_tokens",-1));
    }

    private static void recordMemory(JSONObject receipt,MemoryAvailability value,String phase){
        put(receipt,"available_memory_"+phase+"_bytes",value.availableBytes);
        put(receipt,"available_memory_"+phase+"_source",value.source);
        put(receipt,"activity_manager_available_"+phase+"_bytes",value.activityManagerAvailable);
        put(receipt,"activity_manager_total_"+phase+"_bytes",value.activityManagerTotal);
        put(receipt,"activity_manager_low_memory_"+phase,value.lowMemory);
        put(receipt,"kernel_memavailable_"+phase+"_bytes",value.kernelAvailable==null?JSONObject.NULL:value.kernelAvailable);
        put(receipt,"kernel_memtotal_"+phase+"_bytes",value.kernelTotal==null?JSONObject.NULL:value.kernelTotal);
        put(receipt,"kernel_memory_"+phase+"_status",value.kernelStatus);
        put(receipt,"kernel_memory_"+phase+"_detail",value.detail==null?JSONObject.NULL:value.detail);
        put(receipt,"memory_measurement_"+phase+"_valid",value.measurementValid);
    }

    private static void validateText(String text, boolean required) throws IOException {
        if (text == null || text.isEmpty()) { if (required) throw new IOException("prompt is empty"); return; }
        if (text.indexOf('\0') >= 0 || text.getBytes(StandardCharsets.UTF_8).length > TEXT_LIMIT)
            throw new IOException("text exceeds 65536 UTF-8 bytes or contains NUL");
        try { ConservativeTokenBudget.bytesUpper(text); }
        catch (IllegalArgumentException invalid) { throw new IOException("invalid Unicode prompt", invalid); }
    }
    private static void privateDirectory(File dir) throws Exception {
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("cannot create private directory " + dir);
        Os.chmod(dir.getPath(), 0700);
    }
    private static void writePrivate(File file, byte[] data) throws IOException {
        try (FileOutputStream out = new FileOutputStream(file, false)) { out.write(data); out.getFD().sync(); }
        try { Os.chmod(file.getPath(), 0600); } catch (Exception e) { throw new IOException(e); }
    }
    private static byte[] readBounded(File file, int maximum) throws IOException {
        if (!file.isFile() || file.length() > maximum) throw new IOException("file missing or above bound: " + file.getName());
        try (InputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int n;
            while ((n = in.read(buffer)) != -1) {
                if (out.size() + n > maximum) throw new IOException("file grew beyond bound");
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }
    private static String sha256(byte[] bytes) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder result = new StringBuilder(64);
            for (byte b : hash) result.append(String.format(Locale.US, "%02x", b & 255));
            return result.toString();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
    private static void put(JSONObject target, String key, Object value) {
        try { target.put(key, value); } catch (Exception e) { throw new IllegalStateException(e); }
    }
    @Override public synchronized void close() {
        if (closed.compareAndSet(false, true)) {
            RunHandle h = active.get(); if (h != null) h.cancel();
            WarmTask task=warmActive.get();
            if(task!=null){
                task.ending.set(true);
                synchronized(task){if(task.finisher==null)task.finisher=executor.submit(()->finishWarmOwned(task));}
            }
            executor.shutdown();
        }
    }
}
