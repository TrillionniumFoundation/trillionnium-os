package org.trillionnium.hepta.local;

/** Separate, explicit model-only VLM profile; never changes the text model catalogue. */
public final class UiVenusPins {
    private UiVenusPins() {}
    public static final String WORKER="libhepta_ui_venus_runner.so";
    public static final String WORKER_SHA="5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551";
    public static final long WORKER_BYTES=58144L;
    public static final String MODEL_DIRECTORY="ui-venus-model";
    public static final String MODEL_REPO="bartowski/UI-Venus-2-9B-GGUF";
    public static final String MODEL_REVISION="3d2022e8bbe1fb95f12ca530a9d6ef063807d593";
    public static final String PROFILE="ui-venus2-9b-q4_0-f16-mmproj";
    public static final String SDK_COMMIT="071f609995470bdb0e0769ab964754adfaab7e47";
    public static final String LLAMA_COMMIT="19cce6919992fdffd92e0ac152caaf1e2b8f254e";
    public static final String TEMPLATE_SHA="4a3d47f53cc133e5dc859e9532fcb74baf0459ef426b8f107a3ac6e5926533e5";
    public static final String OFFICIAL_REVISION="6d5f8baf3d28868b3e32fefa9da501e99964a8c5";
    public static final String OFFICIAL_FILE_SHA="7210de8fbe52a6f02d2eacf022050a8c32b4886e453039b204c6400592c01375";
    public static final String OFFICIAL_SYSTEM_SHA="627c1f85167d72994d7d3c9da686456d1e9fd0eb3c8438605a1a8596f6e5efa3";
    public static final int CONTEXT=8192, MAX_TOKENS=1024;
    public static final long DEADLINE_MS=300000L, MIN_AVAILABLE_BYTES=8L*1024*1024*1024;
    public static final class FilePin {
        public final String name,sha256; public final long bytes;
        FilePin(String name,long bytes,String sha){this.name=name;this.bytes=bytes;this.sha256=sha;}
    }
    public static FilePin[] models(){return new FilePin[]{
        new FilePin("UI-Venus-2-9B-Q4_0.gguf",5482832672L,"2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb"),
        new FilePin("mmproj-UI-Venus-2-9B-f16.gguf",918165664L,"6ef77c3bf87391664be7cd71c595352e7281dabe52f24e961e2deace550f3af2")};}
    public static FilePin[] sdk(){return new FilePin[]{
        new FilePin("libgeniex.so",19781824L,"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56"),
        new FilePin("libgeniex_plugin_llama_cpp.so",377040L,"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a"),
        new FilePin("libggml-base.so",3534496L,"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40"),
        new FilePin("libggml-cpu.so",936328L,"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b"),
        new FilePin("libggml-hexagon.so",3874328L,"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f"),
        new FilePin("libggml-htp-v79.so",858848L,"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5"),
        new FilePin("libggml-opencl.so",7886880L,"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875"),
        new FilePin("libggml.so",41088L,"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149"),
        new FilePin("libllama-common.so",6242864L,"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122"),
        new FilePin("libllama.so",5642424L,"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835"),
        new FilePin("libmtmd.so",1643536L,"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d"),
        new FilePin("libomp.so",1234864L,"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76")};}
    public static boolean workerQualified(){return WORKER_BYTES>0 && WORKER_SHA.matches("[0-9a-f]{64}");}
}
