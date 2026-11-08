package org.trillionnium.hepta.local;

/** Fixed model/runtime identity, with a small explicit local hardware configuration. */
public final class LocalRuntimeConfig {
    public static final String MODEL_ID = "LiquidAI/LFM3-1.7B-GGUF";
    public static final String MODEL_FILE = "LFM3-1.7B-QAD-Q4_0.gguf";
    public static final String MODEL_SHA256 = "43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452";
    public static final long MODEL_BYTES = 1049615680L;
    public static final String RUNTIME = "llama_cpp";
    public static final String MODE = "llm";
    public static final String SDK_VERSION = "0.10.0";
    public static final int GENERATION_TOKENS = 256;
    public final String compute;
    public final int contextTokens, threads;

    public LocalRuntimeConfig(String compute, int contextTokens, int threads) {
        if (!"npu".equals(compute) && !"gpu".equals(compute))
            throw new IllegalArgumentException("compute must be exactly npu or gpu; no automatic fallback");
        if (contextTokens != 4096 && contextTokens != 8192)
            throw new IllegalArgumentException("context_tokens must be 4096 or 8192");
        if (threads < 1 || threads > 8)
            throw new IllegalArgumentException("threads must be 1..8");
        this.compute = compute;
        this.contextTokens = contextTokens;
        this.threads = threads;
    }

    public static LocalRuntimeConfig defaults() { return new LocalRuntimeConfig("npu", 4096, 4); }
    public String expectedDevice() { return "npu".equals(compute) ? "HTP0" : "GPUOpenCL"; }
    public boolean matchesResolvedDevice(String device, boolean warningPresent, int gpuLayers) {
        return expectedDevice().equals(device) && !warningPresent && gpuLayers != 0;
    }
}
