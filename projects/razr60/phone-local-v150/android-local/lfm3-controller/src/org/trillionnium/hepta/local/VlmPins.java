package org.trillionnium.hepta.local;

/** Pinned current-frame runner. Qualification is established by separate receipts. */
public final class VlmPins {
    private VlmPins() {}
    public static final String WORKER="libhepta_local_vlm_runner.so";
    public static final long WORKER_BYTES=147544L;
    public static final String WORKER_SHA="079c30132cb55fa89480c4436fa2a11908d87025bba878907b04b83373eef63c";
    public static final String PROJECTOR="GUI-Owl-1.5-4B-Instruct.mmproj-f16.gguf";
    public static final long PROJECTOR_BYTES=836180288L;
    public static final String PROJECTOR_SHA="eabdc0291d460f2e68874f51044030a7da8fe956c2a6b86abd69fd701227c105";
    public static final String PROJECTOR_REPOSITORY="mradermacher/GUI-Owl-1.5-4B-Instruct-GGUF";
    public static final String PROJECTOR_REVISION="f77e8a457158e773d9f3135ff0cac5811878d3b7";
    public static final String TEMPLATE_SHA="3636d0f0bd6bef02654cdffdc447b79cb2cef8ab02cc75267345946291a489e4";
    public static final int IMAGE_BYTES_LIMIT=32*1024*1024;
    public static final long COMPLETION_GRACE_MILLIS=24000L;
}
