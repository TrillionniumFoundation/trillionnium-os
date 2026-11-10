package org.trillionnium.hepta.local;

/** Closed artifact allowlist. Names never select an arbitrary path or model family. */
public final class ModelProfile {
    public static final String LLAMA_COMMIT="19cce6919992fdffd92e0ac152caaf1e2b8f254e";
    public static final ModelProfile LFM3=new ModelProfile("lfm3-1.7b-qad-q4_0","LFM3-1.7B",
            "LiquidAI/LFM3-1.7B-GGUF","", "LFM3-1.7B-QAD-Q4_0.gguf",1049615680L,
            "43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452","lfm3",false,3L<<30);
    public static final ModelProfile MINICPM5=new ModelProfile("minicpm5-2b-q4_k_m","MiniCPM5-2B",
            "openbmb/MiniCPM5-2B-GGUF","2079a22f3beaa4e306449978533478fe0522f4b3","MiniCPM5-2B-Q4_K_M.gguf",1561318368L,
            "ec2d5801640099e97d8d7e8003ad4d81f336e757811f03a26173dddf386602fd","llama",true,3L<<30);
    public static final ModelProfile SPARK=new ModelProfile("spark-x2.6-4b-q4_k_m","Spark-X2.6-4B",
            "XHToken/Spark-X2.6-4B-GGUF","9d716770ac7477776de5f891f70cdf98b003a5cd","Spark-X2.6-4B-Q4_K_M.gguf",3543441312L,
            "91cb2811aebb47ac916aa619d27d4cdd7f4143106b7917accb8ead4cd7f5cbd9","spark2_5",true,5L<<30);
    // These are admission thresholds for qualification, not measured peak RAM.
    // GGUF text qualification does not admit a projector or image in this worker.
    public static final ModelProfile GEMMA4_E4B=new ModelProfile("gemma4-e4b-qat-q4_0","Gemma 4 E4B QAT",
            "google/gemma-4-E4B-it-qat-q4_0-gguf","4b4a2c1d584be7264f87aac328a1bc739ce81b6c","gemma-4-E4B_q4_0-it.gguf",5154941280L,
            "676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee","gemma4",true,7L<<30);
    public static final ModelProfile GEMMA4_E2B=new ModelProfile("gemma4-e2b-qat-q4_0","Gemma 4 E2B QAT",
            "google/gemma-4-E2B-it-qat-q4_0-gguf","675cff42a74c774d6cb76f76d8eacb49b48c9b93","gemma-4-E2B_q4_0-it.gguf",3349516256L,
            "fa401b55b07ee70a54c6dae3903c783a6e65064312529ea57175cb5f8dec6634","gemma4",true,5L<<30);
    // Experimental text-only candidate. The 8 GiB admission threshold is not a
    // measured peak; first device qualification is restricted to context 4096.
    public static final ModelProfile BOLT_E4B=new ModelProfile("nemotron-3.5-bolt-e4b-q4_k_m","Nemotron 3.5 Bolt E4B（实验）",
            "nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB","1db54d5b12533ff1bcaa8e42cf4c667988a1f1be","Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf",6180446208L,
            "c8af2b8aea10a690a1d9491db744a9446660173cb38fc489612b556615a69612","gemma4",true,8L<<30);
    // Experimental text-only MoE. This 7 GiB qualification threshold is not a
    // measured peak and does not treat active parameters as resident weight size.
    public static final ModelProfile LFM25_8B_A1B=new ModelProfile("lfm2.5-8b-a1b-q4_0","LFM2.5-8B-A1B（实验）",
            "LiquidAI/LFM2.5-8B-A1B-GGUF","49c14831707011e64d70b2ebd8462ba08d608434","LFM2.5-8B-A1B-Q4_0.gguf",4844678368L,
            "48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715","lfm2moe",true,7L<<30);
    // Experimental text-only Qwen candidate. The 5 GiB admission threshold is
    // qualification headroom, not a measured peak. No projector is admitted.
    public static final ModelProfile QWEN35_4B=new ModelProfile("qwen3.5-4b-q4_0","Qwen 3.5 4B（实验）",
            "unsloth/Qwen3.5-4B-GGUF","e87f176479d0855a907a41277aca2f8ee7a09523","Qwen3.5-4B-Q4_0.gguf",2583221408L,
            "298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb","qwen35",true,5L<<30);
    // Experimental 9B text-only candidate. This 8 GiB admission threshold is
    // qualification headroom, not measured peak RAM. Vision is not admitted.
    public static final ModelProfile QWEN35_9B=new ModelProfile("qwen3.5-9b-q4_0","Qwen 3.5 9B（实验）",
            "unsloth/Qwen3.5-9B-GGUF","3885219b6810b007914f3a7950a8d1b469d598a5","Qwen3.5-9B-Q4_0.gguf",5379417312L,
            "17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24","qwen35",true,8L<<30);
    // Experimental text candidates; RAM gates are not measured peaks or qualification.
    public static final ModelProfile BONSAI2_9B=new ModelProfile("bonsai2-9b-q2_0","Bonsai 2 9B（实验）",
            "prism-ml/Ternary-Bonsai-2-9B-gguf","82265ccc78ddaac4700286a35e9badcc32376dd9","Ternary-Bonsai-2-9B-Q2_0.gguf",2556640128L,
            "1f884aa56aacd2bbbb2e4b7abaead2b1102b74a9c75a23fc33dab916813a384d","qwen35",true,6L<<30);
    public static final ModelProfile ORVENA4B=new ModelProfile("orvena-4b-q4_k_m","Orvena 4B（实验）",
            "mradermacher/Orvena-4B-GGUF","a2f0300d9c43ee0911610d791ec3bfd302aafa6c","Orvena-4B.Q4_K_M.gguf",2783447904L,
            "c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57","qwen35",true,5L<<30);
    // Experimental text-only candidate; the first device qualification plan
    // uses context 4096. The 6 GiB admission threshold is not a measured peak.
    public static final ModelProfile NANBEIGE42_3B=new ModelProfile("nanbeige4.2-3b-q4_k_m","Nanbeige4.2 3B（实验）",
            "bartowski/Nanbeige_Nanbeige4.2-3B-GGUF","210b0d6d6c1046044c7ea9d16c9ce3b5716ec2d2","Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf",2684023968L,
            "b92d2e35c9876b0c4bc671996360204f4149d0546c23d5954d5eb3b106c81f24","nanbeige",true,6L<<30);
    public final String id,displayName,repository,revision,fileName,sha256,architecture;
    public final long bytes,minimumAvailableBytes;
    public final boolean exactTokenizationRequired;
    private ModelProfile(String id,String displayName,String repository,String revision,String fileName,long bytes,
                         String sha256,String architecture,boolean exact,long minimumAvailableBytes){
        this.id=id;this.displayName=displayName;this.repository=repository;this.revision=revision;
        this.fileName=fileName;this.bytes=bytes;this.sha256=sha256;this.architecture=architecture;
        this.exactTokenizationRequired=exact;this.minimumAvailableBytes=minimumAvailableBytes;
    }
    public static ModelProfile named(String id){
        if(LFM3.id.equals(id))return LFM3;
        if(LFM25_8B_A1B.id.equals(id))return LFM25_8B_A1B;
        if(MINICPM5.id.equals(id))return MINICPM5;
        if(SPARK.id.equals(id))return SPARK;
        if(GEMMA4_E4B.id.equals(id))return GEMMA4_E4B;
        if(GEMMA4_E2B.id.equals(id))return GEMMA4_E2B;
        if(BOLT_E4B.id.equals(id))return BOLT_E4B;
        if(QWEN35_4B.id.equals(id))return QWEN35_4B;
        if(QWEN35_9B.id.equals(id))return QWEN35_9B;
        if(BONSAI2_9B.id.equals(id))return BONSAI2_9B;
        if(ORVENA4B.id.equals(id))return ORVENA4B;
        if(NANBEIGE42_3B.id.equals(id))return NANBEIGE42_3B;
        throw new IllegalArgumentException("unknown pinned model_profile");
    }
}
