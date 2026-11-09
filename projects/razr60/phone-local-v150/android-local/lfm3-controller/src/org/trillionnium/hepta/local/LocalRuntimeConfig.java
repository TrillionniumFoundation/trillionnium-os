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
    public final ModelProfile profile;
    public final int contextTokens, threads;

    public LocalRuntimeConfig(String compute, int contextTokens, int threads) {
        this(ModelProfile.LFM3,compute,contextTokens,threads);
    }

    public LocalRuntimeConfig(ModelProfile profile,String compute, int contextTokens, int threads) {
        if(profile==null)throw new IllegalArgumentException("model profile is required");
        if (!"npu".equals(compute) && !"gpu".equals(compute))
            throw new IllegalArgumentException("compute must be exactly npu or gpu; no automatic fallback");
        if (contextTokens != 4096 && contextTokens != 8192)
            throw new IllegalArgumentException("context_tokens must be 4096 or 8192");
        if (threads < 1 || threads > 8)
            throw new IllegalArgumentException("threads must be 1..8");
        this.compute = compute;
        this.profile = profile;
        this.contextTokens = contextTokens;
        this.threads = threads;
    }

    public static LocalRuntimeConfig defaults() { return new LocalRuntimeConfig("npu", 8192, 4); }
    public static LocalRuntimeConfig fromFields(java.util.Map<String,?> value){
        if(value==null)throw new IllegalArgumentException("runtime config required");
        boolean legacy="hepta.local-runtime.v1".equals(value.get("schema"));
        if(!legacy&&!"hepta.local-runtime.v2".equals(value.get("schema")))throw new IllegalArgumentException("unknown runtime-config schema");
        java.util.Set<String> keys=new java.util.HashSet<>(java.util.Arrays.asList("schema","compute","context_tokens","threads"));
        if(!legacy)keys.add("model_profile");
        if(!keys.equals(value.keySet()))throw new IllegalArgumentException("missing or unknown runtime-config field");
        if(!(value.get("compute") instanceof String)||!(value.get("context_tokens") instanceof Integer)
                ||!(value.get("threads") instanceof Integer)||(!legacy&&!(value.get("model_profile") instanceof String)))
            throw new IllegalArgumentException("runtime-config types differ");
        ModelProfile selected=legacy?ModelProfile.LFM3:ModelProfile.named((String)value.get("model_profile"));
        return new LocalRuntimeConfig(selected,(String)value.get("compute"),(Integer)value.get("context_tokens"),(Integer)value.get("threads"));
    }
    public String expectedDevice() { return "npu".equals(compute) ? "HTP0" : "GPUOpenCL"; }
    public boolean matchesResolvedDevice(String device, boolean warningPresent, int gpuLayers) {
        return expectedDevice().equals(device) && !warningPresent && gpuLayers != 0;
    }
}
