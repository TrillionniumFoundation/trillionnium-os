package org.trillionnium.hepta.gpuprobe;

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

/** One local request at a time. Explicit GPU profiles are diagnostics only. */
public final class LocalModelEngine implements AutoCloseable {
    public static final long MIN_AVAILABLE_BYTES = 5L * 1024 * 1024 * 1024;
    private static final int TEXT_LIMIT = 65536;
    private static final int IMAGE_LIMIT = 8 * 1024 * 1024;
    private static final int OUTPUT_LIMIT = 1024 * 1024;
    private final Context context;
    private final File files;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final AtomicReference<RunHandle> PROCESS_ACTIVE = new AtomicReference<>();
    private final AtomicReference<RunHandle> active = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private volatile Result lastResult;

    public LocalModelEngine(Context context) {
        this.context = context.getApplicationContext();
        this.files = this.context.getFilesDir();
    }

    public static final class Request {
        public final String prompt, systemPrompt;
        public final File imageOrNull;
        public final int maxTokens;
        public final long timeoutMs;
        public final RuntimeProfile profile;
        public Request(String prompt, String systemPrompt, File imageOrNull, int maxTokens, long timeoutMs) {
            this(prompt,systemPrompt,imageOrNull,maxTokens,timeoutMs,RuntimeProfile.LLAMA_GPU_CPU_VISION);
        }
        public Request(String prompt, String systemPrompt, File imageOrNull, int maxTokens, long timeoutMs,RuntimeProfile profile) {
            this.prompt = prompt;
            this.systemPrompt = systemPrompt;
            this.imageOrNull = imageOrNull;
            this.maxTokens = maxTokens;
            this.timeoutMs = timeoutMs;
            this.profile = Objects.requireNonNull(profile,"runtime profile required");
        }
    }

    public interface Listener { void onFinished(Result result); }

    public static final class Result {
        public final String runId, status, rawText;
        public final Integer exitCode;
        public final boolean processExitObserved, inferenceCompleted;
        public final JSONObject nativeReceipt, receipt;
        public final File runDirectory;
        Result(String runId, String status, String rawText, Integer exitCode,
                boolean processExitObserved, boolean inferenceCompleted,
                JSONObject nativeReceipt, JSONObject receipt, File runDirectory) {
            this.runId=runId; this.status=status; this.rawText=rawText; this.exitCode=exitCode;
            this.processExitObserved=processExitObserved; this.inferenceCompleted=inferenceCompleted;
            this.nativeReceipt=nativeReceipt; this.receipt=receipt; this.runDirectory=runDirectory;
        }
    }

    public static final class RunHandle {
        public final String runId = UUID.randomUUID().toString().replace("-", "");
        private final AtomicBoolean cancelRequested = new AtomicBoolean(false);
        private final AtomicReference<Process> child = new AtomicReference<>();
        public void cancel() {
            cancelRequested.set(true);
            Process p = child.get();
            if (p != null && p.isAlive()) p.destroy();
        }
        public boolean isCancellationRequested() { return cancelRequested.get(); }
    }

    public RunHandle start(final Request request, final Listener listener) {
        if (request == null || listener == null) throw new IllegalArgumentException("request and listener required");
        if (closed.get()) throw new IllegalStateException("engine is closed");
        final RunHandle handle = new RunHandle();
        if (!PROCESS_ACTIVE.compareAndSet(null, handle)) throw new IllegalStateException("local model already has an active request in this app process");
        active.set(handle);
        try {
            executor.execute(() -> execute(handle, request, listener));
        } catch (RuntimeException e) {
            active.compareAndSet(handle, null);
            PROCESS_ACTIVE.compareAndSet(handle, null);
            throw e;
        }
        return handle;
    }

    public boolean isBusy() { return PROCESS_ACTIVE.get() != null; }
    public Result lastResult() { return lastResult; }
    public void cancelActive() { RunHandle h = active.get(); if (h != null) h.cancel(); }
    public File modelDirectory() { return new File(files, "model"); }
    public File modelDirectory(RuntimeProfile profile) { return new File(files,profile.modelSubdirectory); }
    public long availableMemoryBytes() {
        ActivityManager.MemoryInfo info = memoryInfo();
        return info.availMem;
    }
    private ActivityManager.MemoryInfo memoryInfo() {
        ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
        ((ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE)).getMemoryInfo(info);
        return info;
    }

    private void execute(RunHandle h, Request r, Listener listener) {
        long start = SystemClock.elapsedRealtime();
        File run = new File(new File(files, "runs"), h.runId);
        JSONObject receipt = new JSONObject(), nativeResult = new JSONObject();
        String raw = "", status = "preflight_failed", error = null;
        Integer exit = null;
        boolean observed = false, complete = false, timedOut = false, forceSent = false;
        Process process = null;
        try {
            privateDirectory(files.getCanonicalFile());
            privateDirectory(new File(files, "runs").getCanonicalFile());
            privateDirectory(run = run.getCanonicalFile());
            put(receipt, "schema", "hepta.appuid-probe.receipt.v1");
            put(receipt, "run_id", h.runId);
            put(receipt, "app_uid", android.os.Process.myUid());
            put(receipt, "app_pid", android.os.Process.myPid());
            put(receipt, "package_name", context.getPackageName());
            put(receipt, "runtime_profile", r.profile.id);
            put(receipt, "runtime", r.profile.runtime);
            put(receipt, "compute_requested", r.profile.compute);
            put(receipt, "vision_device_requested", r.profile.visionDevice==null?JSONObject.NULL:r.profile.visionDevice);
            put(receipt, "context_tokens_requested",r.profile.contextTokens);
            put(receipt, "diagnostic_only_profile",r.profile.isGpuDiagnostic());
            put(receipt, "sdk_version_expected", "0.10.0");
            put(receipt, "production_agent_ready", false);
            put(receipt, "phone_actions_supported", false);
            put(receipt, "automatic_retry", false);
            put(receipt, "started_wall_ms", System.currentTimeMillis());
            put(receipt, "minimum_available_memory_bytes", MIN_AVAILABLE_BYTES);
            validateText(r.prompt, true);
            validateText(r.systemPrompt, false);
            if (r.maxTokens < 1 || r.maxTokens > 1024) throw new IOException("maxTokens must be 1..1024");
            if (r.timeoutMs < 1000 || r.timeoutMs > 300000) throw new IOException("timeoutMs must be 1000..300000");
            ActivityManager.MemoryInfo memory = memoryInfo();
            put(receipt, "available_memory_before_bytes", memory.availMem);
            put(receipt, "total_memory_bytes", memory.totalMem);
            put(receipt, "android_low_memory", memory.lowMemory);
            if (memory.lowMemory || memory.availMem < MIN_AVAILABLE_BYTES) {
                status = "insufficient_memory";
                throw new IOException("local model refused: available RAM below conservative 5 GiB threshold or Android reports low memory");
            }
            File model = modelDirectory(r.profile).getCanonicalFile();
            if (!model.getParentFile().equals(files.getCanonicalFile()) || !model.isDirectory())
                throw new IOException("model must be imported into the selected app-private model directory");
            String[] modelEntries = model.list();
            if (modelEntries == null || modelEntries.length == 0) throw new IOException("selected model directory is empty");
            File modelConfig = new File(model,r.profile.modelName).getCanonicalFile();
            if (!modelConfig.getParentFile().equals(model) || !modelConfig.isFile() || modelConfig.length() == 0)
                throw new IOException("nonempty canonical model entry is required: "+r.profile.modelName);
            File projector=null;
            if(r.profile.isGpuDiagnostic()){
                validateGguf(modelConfig);
                projector=new File(model,r.profile.projectorName).getCanonicalFile();
                if(!projector.getParentFile().equals(model)||!projector.isFile())throw new IOException("canonical private mmproj.gguf is required");
                validateGguf(projector);
                if(reservedMarker(r.prompt)||reservedMarker(r.systemPrompt))
                    throw new IOException("reserved image marker is forbidden in raw diagnostic text");
            }
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File runner = new File(nativeDir,r.profile.runnerName).getCanonicalFile();
            if (!runner.getParentFile().equals(nativeDir) || !runner.isFile() || !runner.canExecute())
                throw new IOException("installed nativeLibraryDir runner unavailable");
            if (!new File(nativeDir,r.profile.pluginName).isFile()) throw new IOException("selected local plugin not installed");
            put(receipt, "model_directory", model.getPath());
            put(receipt, "model_config", modelConfig.getPath());
            put(receipt, "model_format",r.profile.isGpuDiagnostic()?"gguf":"qairt_context_binary");
            put(receipt, "model_file_bytes",modelConfig.length());
            put(receipt, "projector_file",projector==null?JSONObject.NULL:projector.getPath());
            put(receipt, "projector_file_bytes",projector==null?JSONObject.NULL:projector.length());
            put(receipt, "native_library_directory", nativeDir.getPath());
            put(receipt, "runner_path", runner.getPath());
            File prompt = new File(run, "prompt.txt"), system = new File(run, "system.txt");
            writePrivate(prompt, r.prompt.getBytes(StandardCharsets.UTF_8));
            if (r.systemPrompt != null && !r.systemPrompt.isEmpty()) writePrivate(system, r.systemPrompt.getBytes(StandardCharsets.UTF_8));
            File image = null;
            if (r.imageOrNull != null) {
                File source = r.imageOrNull.getCanonicalFile();
                String privatePrefix = files.getCanonicalPath() + File.separator;
                if (!source.getPath().startsWith(privatePrefix)) throw new IOException("image must already be in this app's private files directory");
                byte[] imageBytes = readBounded(source, IMAGE_LIMIT);
                if (imageBytes.length == 0) throw new IOException("image is empty");
                if(r.profile.isGpuDiagnostic()){
                    writePrivate(new File(run,"image-original.bin"),imageBytes);
                    put(receipt,"image_original_sha256",sha256(imageBytes));
                    ProbeImagePreprocessor.Result prepared=ProbeImagePreprocessor.prepare(imageBytes);
                    imageBytes=prepared.png;
                    put(receipt,"image_transform",prepared.transform);
                }
                image = new File(run, "image.bin");
                writePrivate(image, imageBytes);
                put(receipt, "image_sha256", sha256(imageBytes));
            }
            String generationMode=image==null?"llm":"vlm";
            String actualVision=image==null?null:r.profile.visionDevice;
            put(receipt,"vision_device_requested",actualVision==null?JSONObject.NULL:actualVision);
            put(receipt,"mode",generationMode);
            File resultFile = new File(run, "native-result.json"), rawFile = new File(run, "raw-text.txt");
            File stdout = new File(run, "stdout.log"), stderr = new File(run, "stderr.log");
            writePrivate(stdout, new byte[0]); writePrivate(stderr, new byte[0]);
            List<String> args = new ArrayList<>(Arrays.asList(runner.getPath(),
                "--request-id", h.runId, "--mode",generationMode, "--runtime",r.profile.runtime,"--compute",r.profile.compute,
                "--model", modelConfig.getPath(), "--prompt-file", prompt.getPath(),
                "--result-file", resultFile.getPath(), "--text-file", rawFile.getPath(),
                "--ctx-size",Integer.toString(r.profile.contextTokens),"--max-tokens",Integer.toString(r.maxTokens),
                "--threads", "4", "--timeout-ms", Long.toString(r.timeoutMs), "--log-level", "info"));
            if(projector!=null&&image!=null){args.add("--mmproj");args.add(projector.getPath());}
            if(actualVision!=null){args.add("--vit-device");args.add(actualVision);}
            if (system.isFile()) { args.add("--system-file"); args.add(system.getPath()); }
            if (image != null) { args.add("--image"); args.add(image.getPath()); }
            put(receipt, "argv", new JSONArray(args));
            put(receipt, "prompt_sha256", sha256(r.prompt.getBytes(StandardCharsets.UTF_8)));
            put(receipt, "grammar_constraint_enabled", false);
            put(receipt, "stdout_file", stdout.getPath()); put(receipt, "stderr_file", stderr.getPath());
            if (h.cancelRequested.get()) { status = "cancelled_before_start"; throw new IOException("cancel requested before start"); }
            ProcessBuilder builder = new ProcessBuilder(args);
            builder.directory(run);
            builder.redirectOutput(stdout); builder.redirectError(stderr);
            Map<String, String> env = builder.environment();
            env.put("LD_LIBRARY_PATH", nativeDir.getPath() + ":/vendor/lib64");
            env.put("ADSP_LIBRARY_PATH", nativeDir.getPath() + ";/vendor/lib/rfsa/adsp;/system/lib/rfsa/adsp;/dsp");
            env.put("HEPTA_PROBE_NATIVE_LIB_DIR", nativeDir.getPath());
            env.remove("GENIEX_QAIRT_LIB");
            env.remove("GENIEX_PLUGIN_PATH");
            process = builder.start(); h.child.set(process);
            put(receipt, "process_started", true);
            status = "running";
            long launched = SystemClock.elapsedRealtime(), terminationAt = 0;
            while (true) {
                if (process.waitFor(200, TimeUnit.MILLISECONDS)) { exit = process.exitValue(); observed = true; break; }
                long now = SystemClock.elapsedRealtime();
                if (now - launched > r.timeoutMs + 2000) timedOut = true;
                if (h.cancelRequested.get() || timedOut) {
                    if (terminationAt == 0) { terminationAt = now; process.destroy(); }
                    if (!forceSent && now - terminationAt >= 2000) { process.destroyForcibly(); forceSent = true; }
                    if (now - terminationAt >= 12000) { status = "termination_unknown"; break; }
                }
            }
            if (rawFile.isFile()) raw = new String(readBounded(rawFile, OUTPUT_LIMIT), StandardCharsets.UTF_8);
            if (resultFile.isFile()) nativeResult = new JSONObject(new String(readBounded(resultFile, OUTPUT_LIMIT), StandardCharsets.UTF_8));
            boolean binding = "hepta.geniex-once.result.v1".equals(nativeResult.optString("schema"))
                && h.runId.equals(nativeResult.optString("request_id"))
                && generationMode.equals(nativeResult.optString("mode"))
                && r.profile.runtime.equals(nativeResult.optString("runtime"))
                && r.profile.compute.equals(nativeResult.optString("compute_requested"))
                && r.profile.resolvedDevice.equals(nativeResult.optString("device_resolved"))
                && nativeResult.has("device_warning") && nativeResult.isNull("device_warning")
                && modelConfig.getPath().equals(nativeResult.optString("model_path"))
                && (actualVision==null?nativeResult.has("vit_device_requested")&&nativeResult.isNull("vit_device_requested"):
                    actualVision.equals(nativeResult.optString("vit_device_requested")))
                && nativeResult.optInt("n_ctx_create",-1)==r.profile.contextTokens
                && !nativeResult.optBoolean("raw_text_truncated", true)
                && nativeResult.optBoolean("raw_text_utf8", false)
                && rawFile.isFile()
                && sha256(readBounded(rawFile, OUTPUT_LIMIT)).equals(nativeResult.optString("raw_text_sha256"))
                && rawFile.length() == nativeResult.optLong("raw_text_bytes", -1);
            put(receipt, "native_result_binding_valid", binding);
            String diagnosticLog=new String(readBounded(stderr,8*1024*1024),StandardCharsets.UTF_8);
            boolean visionFallback=diagnosticLog.contains("mtmd failed to initialize the vision encoder");
            boolean visionLoaded=image==null||(diagnosticLog.contains("Using vision device override: "+actualVision)&&diagnosticLog.contains("mmproj loaded: vision=true"));
            put(receipt,"vision_fallback_detected",visionFallback);
            put(receipt,"vision_load_log_evidence",visionLoaded);
            put(receipt,"backend_qualification_requires_device_evidence",true);
            boolean contextBudgetValid=!r.profile.isGpuDiagnostic()||verifiedGpuBudget(nativeResult,r.maxTokens,image!=null);
            put(receipt,"native_context_budget_valid",contextBudgetValid);
            complete = observed && exit != null && exit == 0 && binding
                && contextBudgetValid && !visionFallback && visionLoaded
                && nativeResult.optBoolean("generation_complete", false)
                && !h.cancelRequested.get() && !timedOut;
            if (observed) status = complete ? "completed" : h.cancelRequested.get() ? "cancelled" : timedOut ? "timed_out" : "native_failed";
            if (!complete && error == null) error = !nativeResult.isNull("error")?nativeResult.optString("error"):!binding?"native receipt binding failed":!contextBudgetValid?"native exact context budget failed":visionFallback?"vision backend fallback detected":!visionLoaded?"vision encoder load evidence absent":"native inference did not complete";
        } catch (Throwable e) {
            error = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
            if (process != null && process.isAlive()) {
                process.destroy();
                try {
                    if (!process.waitFor(2000, TimeUnit.MILLISECONDS)) { process.destroyForcibly(); forceSent = true; }
                    if (process.waitFor(10000, TimeUnit.MILLISECONDS)) { observed = true; exit = process.exitValue(); }
                } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            }
            if (process != null && !observed && !process.isAlive()) { observed = true; exit = process.exitValue(); }
            if (process != null && !observed) status = "termination_unknown";
            else if (process != null) status = h.cancelRequested.get() ? "cancelled" : "engine_failed";
            complete = false;
        } finally {
            put(receipt, "status", status);
            put(receipt, "error", error == null ? JSONObject.NULL : error);
            put(receipt, "process_started", process != null);
            put(receipt, "process_exit_observed", observed);
            put(receipt, "exit_code", exit == null ? JSONObject.NULL : exit);
            put(receipt, "inference_completed", complete);
            put(receipt, "cancel_requested", h.cancelRequested.get());
            put(receipt, "timeout_observed", timedOut);
            put(receipt, "force_destroy_sent", forceSent);
            put(receipt, "elapsed_ms", SystemClock.elapsedRealtime() - start);
            put(receipt, "native_receipt", nativeResult);
            put(receipt, "raw_text_file", new File(run, "raw-text.txt").getPath());
            put(receipt, "raw_text_sha256_read", sha256(raw.getBytes(StandardCharsets.UTF_8)));
            try { writePrivate(new File(run, "app-receipt.json"), receipt.toString(2).getBytes(StandardCharsets.UTF_8)); }
            catch (Exception persistError) { put(receipt, "receipt_write_error", persistError.toString()); }
            final boolean release = process == null || observed;
            if (release) { h.child.set(null); active.compareAndSet(h, null); PROCESS_ACTIVE.compareAndSet(h, null); }
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

    private static void validateGguf(File file)throws IOException{
        if(file.length()<24)throw new IOException("GGUF file is empty or truncated");
        try(FileInputStream input=new FileInputStream(file)){
            byte[] magic=new byte[4];if(input.read(magic)!=4||magic[0]!='G'||magic[1]!='G'||magic[2]!='U'||magic[3]!='F')
                throw new IOException("selected model/projector is not GGUF");
        }
    }
    private static boolean verifiedGpuBudget(JSONObject nativeResult,int maxTokens,boolean image){
        JSONObject budget=nativeResult.optJSONObject("input_budget");
        if(budget==null||!budget.optBoolean("checked",false)||!budget.optBoolean("admitted",false))return false;
        long tokens=budget.optLong("input_tokens",-1),margin=budget.optLong("additional_reserve",-1);
        return "llama_mtmd_exact".equals(budget.optString("counter"))
            && "19cce6919992fdffd92e0ac152caaf1e2b8f254e".equals(budget.optString("counter_source_commit"))
            && budget.optInt("context_tokens",-1)==8192&&budget.optInt("generation_reserve",-1)==maxTokens
            && tokens>0&&tokens<=8192&&margin==64&&tokens+margin+maxTokens<=8192
            && budget.optBoolean("image_present",false)==image
            && budget.optBoolean("profile_within_counted_bound",false)
            && budget.optBoolean("profile_exact_count_match",false);
    }

    private static boolean reservedMarker(String text){return text!=null&&(text.contains("<__image__>")||text.contains("<__media__>"));}

    private static void validateText(String text, boolean required) throws IOException {
        if (text == null || text.isEmpty()) { if (required) throw new IOException("prompt is empty"); return; }
        if (text.indexOf('\0') >= 0 || text.getBytes(StandardCharsets.UTF_8).length > TEXT_LIMIT)
            throw new IOException("text exceeds 65536 UTF-8 bytes or contains NUL");
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
    @Override public void close() {
        if (closed.compareAndSet(false, true)) {
            RunHandle h = active.get(); if (h != null) h.cancel();
            executor.shutdown();
        }
    }
}
