package org.trillionnium.hepta.gpuprobe;

/** Closed diagnostic-only profiles; no phone action or network API exists. */
public enum RuntimeProfile {
    LLAMA_GPU_CPU_VISION("llama_gpu_cpu_vision", "GGUF / Adreno GPU + CPU 视觉（诊断）", "llama_cpp", "gpu", "GPUOpenCL", "CPU",
        "model-llama", "model.gguf", "mmproj.gguf", 8192, "libhepta_gpu_probe_runner.so", "libgeniex_plugin_llama_cpp.so"),
    LLAMA_GPU_GPU_VISION("llama_gpu_gpu_vision", "GGUF / Adreno GPU + GPU 视觉（诊断）", "llama_cpp", "gpu", "GPUOpenCL", "GPUOpenCL",
        "model-llama", "model.gguf", "mmproj.gguf", 8192, "libhepta_gpu_probe_runner.so", "libgeniex_plugin_llama_cpp.so");

    public final String id, label, runtime, compute, resolvedDevice, visionDevice;
    public final String modelSubdirectory, modelName, projectorName, runnerName, pluginName;
    public final int contextTokens;
    RuntimeProfile(String id,String label,String runtime,String compute,String resolvedDevice,String visionDevice,
            String modelSubdirectory,String modelName,String projectorName,int contextTokens,String runnerName,String pluginName) {
        this.id=id;this.label=label;this.runtime=runtime;this.compute=compute;this.resolvedDevice=resolvedDevice;
        this.visionDevice=visionDevice;this.modelSubdirectory=modelSubdirectory;this.modelName=modelName;
        this.projectorName=projectorName;this.contextTokens=contextTokens;this.runnerName=runnerName;this.pluginName=pluginName;
    }
    public boolean isGpuDiagnostic(){return true;}
    public static RuntimeProfile fromId(String value){
        for(RuntimeProfile profile:values())if(profile.id.equals(value))return profile;
        throw new IllegalArgumentException("unknown local diagnostic runtime profile");
    }
    @Override public String toString(){return label;}
}
