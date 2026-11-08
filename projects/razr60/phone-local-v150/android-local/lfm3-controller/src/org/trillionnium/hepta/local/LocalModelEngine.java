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
    private final AtomicReference<RunHandle> active = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private volatile Result lastResult;
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
            put(receipt, "schema", "hepta.local-model.receipt.v2");
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
            if (!admission.admits(config.profile.minimumAvailableBytes)) {
                status = "insufficient_memory";
                throw new IOException("selected model refused: available physical RAM below profile threshold, invalid measurement, or Android lowMemory=true; source="+admission.source);
            }
            File model = modelDirectory().getCanonicalFile();
            if (!model.getParentFile().equals(files.getCanonicalFile()) || !model.isDirectory())
                throw new IOException("model must be imported into app private files/model");
            File selectedModel = modelFile().getCanonicalFile();
            if (!selectedModel.getParentFile().equals(model) || !selectedModel.getName().equals(config.profile.fileName))
                throw new IOException("only the selected pinned app-private GGUF is accepted");
            if (h.cancelRequested.get()) { status = "cancelled_before_start"; throw new IOException("cancel requested before model verification"); }
            modelVerifier.verify(selectedModel,config.profile, () -> h.cancelRequested.get());
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
                put(receipt,"grammar_schema",DecisionGrammar.SCHEMA);
                put(receipt,"grammar_sha256",r.controllerGrammar.sha256);
                put(receipt,"grammar_observation_id",r.controllerGrammar.observationId);
                put(receipt,"grammar_current_package",r.controllerGrammar.currentPackage);
                put(receipt,"grammar_file",grammar.getPath());
            }
            File resultFile = new File(run, "native-result.json"), rawFile = new File(run, "raw-text.txt");
            File stdout = new File(run, "stdout.log"), stderr = new File(run, "stderr.log");
            writePrivate(stdout, new byte[0]); writePrivate(stderr, new byte[0]);
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
            put(receipt, "argv", new JSONArray(args));
            put(receipt, "prompt_sha256", sha256(r.prompt.getBytes(StandardCharsets.UTF_8)));
            put(receipt, "grammar_constraint_enabled", r.controllerGrammar != null);
            put(receipt, "stdout_file", stdout.getPath()); put(receipt, "stderr_file", stderr.getPath());
            if (h.cancelRequested.get()) { status = "cancelled_before_start"; throw new IOException("cancel requested before start"); }
            ProcessBuilder builder = new ProcessBuilder(args);
            builder.directory(run);
            builder.redirectOutput(stdout); builder.redirectError(stderr);
            Map<String, String> env = builder.environment();
            env.put("LD_LIBRARY_PATH", nativeDir.getPath() + ":/vendor/lib64");
            env.put("ADSP_LIBRARY_PATH", nativeDir.getPath() + ";/vendor/lib/rfsa/adsp;/system/lib/rfsa/adsp;/dsp");
            env.put("HEPTA_LOCAL_NATIVE_LIB_DIR", nativeDir.getPath());
            env.remove("GENIEX_QAIRT_LIB");
            // llama_cpp resolves its backend/DSP libraries from this directory.
            // The native adapter registers the renamed plugin explicitly.
            env.put("GENIEX_PLUGIN_PATH", nativeDir.getPath());
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
            // The native deadline precedes the outer watchdog by two seconds.
            // Its owned exit/identity-bound deadline must retain timeout status.
            if (exit != null && exit == 124) timedOut = true;
            if ("hepta.geniex-once.result.v1".equals(nativeResult.optString("schema"))
                    && h.runId.equals(nativeResult.optString("request_id"))
                    && LocalRuntimeConfig.RUNTIME.equals(nativeResult.optString("runtime"))
                    && nativeResult.optBoolean("deadline_observed", false)) timedOut = true;
            JSONObject nativeInputs=nativeResult.optJSONObject("input_sha256");
            boolean grammarBinding=nativeInputs!=null&&(r.controllerGrammar==null
                ?nativeInputs.has("grammar")&&nativeInputs.isNull("grammar")
                :r.controllerGrammar.sha256.equals(nativeInputs.optString("grammar")));
            put(receipt,"grammar_binding_valid",grammarBinding);
            boolean binding = "hepta.geniex-once.result.v1".equals(nativeResult.optString("schema"))
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
                && sha256(readBounded(rawFile, OUTPUT_LIMIT)).equals(nativeResult.optString("raw_text_sha256"))
                && rawFile.length() == nativeResult.optLong("raw_text_bytes", -1);
            put(receipt, "native_result_binding_valid", binding);
            put(receipt, "runtime_device_selection_valid", config.matchesResolvedDevice(nativeResult.optString("device_resolved"),
                    !nativeResult.has("device_warning") || !nativeResult.isNull("device_warning"), nativeResult.optInt("n_gpu_layers_create", 0)));
            put(receipt, "device_resolved", nativeResult.opt("device_resolved"));
            put(receipt, "native_context_budget_valid", nativeBudgetValid(nativeResult, config, r.maxTokens));
            complete = observed && exit != null && exit == 0 && binding
                && nativeResult.optBoolean("generation_complete", false)
                && !h.cancelRequested.get() && !timedOut;
            if (observed) status = complete ? "completed" : h.cancelRequested.get() ? "cancelled" : timedOut ? "timed_out" : "native_failed";
            if (!complete && error == null) error = nativeResult.optString("error", "native inference did not complete");
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
            else if (h.cancelRequested.get()) status = "cancelled_before_start";
            complete = false;
        } finally {
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
    @Override public void close() {
        if (closed.compareAndSet(false, true)) {
            RunHandle h = active.get(); if (h != null) h.cancel();
            executor.shutdown();
        }
    }
}
