package org.trillionnium.hepta.local;

/** Exact already-built model-only worker/runtime and its original model pins. */
public final class MobiMindPins {
    private MobiMindPins() {}
    public static final String MODEL_REPO="fengerhu1/MobiMind-1.5-2B-W8A8-0717";
    public static final String MODEL_REVISION="f02848b6b7796988ea95df8f78a7b38bd71e2a90";
    public static final String MNN_REVISION="bce7456ce60b5e51b4d3b357f303515860353d8c";
    public static final String WORKER="libhepta_mobimind_runner.so";
    public static final String WORKER_SHA="b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020";
    public static final String MNN_SHA="5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d";
    public static final String CXX_SHA="77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754";
    public static final long WORKER_BYTES=2186768L, MNN_BYTES=6408488L, CXX_BYTES=9236352L;
    public static final String MODEL_DIRECTORY="model/mobimind-1.5-2b-w8a8-0717-f02848b6";
    public static final class FilePin {
        public final String name, sha256; public final long bytes;
        FilePin(String name,long bytes,String sha256){this.name=name;this.bytes=bytes;this.sha256=sha256;}
    }
    public static FilePin[] modelFiles() { return new FilePin[]{
        new FilePin("README.md",1029L,"52bd50ac9e33e6c87ce604ee1ae919d8193c85c9f5a2e338c407dc0d372fc36b"),
        new FilePin("config.json",634L,"6fa0f3c99710b93415a6c7e8adf7e5d03e45c85094e75ff8974ad2f76b0c59b8"),
        new FilePin("configuration.json",49L,"8fbd3c45576d536e5953c933bf7399d0ea57184032b4a98559461e1b285d74a8"),
        new FilePin("embeddings_bf16.bin",622329856L,"b4f4b0a21e9b080729b3de7153b5f29f956e08c5d440c7d2fe4a8258c31178c9"),
        new FilePin("export_args.json",1347L,"48bcffba4773ab9486fe204f7955b42c6ac8133fd79cae81ca9794e8e0e4af7c"),
        new FilePin("llm.mnn",508712L,"176185b5b97c63e3100308f05d2cf31a192352bee0527f29fc6a83a884291297"),
        new FilePin("llm.mnn.weight",2120738968L,"9b550448df562f08efb67b20054579b94e2d730c464f802d2908ac6456ac6cc7"),
        new FilePin("llm_config.json",6056L,"8cbada58b4f5885e78ac6107458f4075a9dadcd12611ad7bb24af5b1f09c0119"),
        new FilePin("tokenizer.mtok",4096835L,"d646d5bff3339247947ad3a0cf317fe2be609f789684db9048b2174a84a5d656"),
        new FilePin("visual.mnn",5238472L,"0ecc507e46773533f7a93703adf1d416d5c6da7400e3f687eb366ce65a2d4c74"),
        new FilePin("visual.mnn.weight",526865248L,"2620be5060322e9c56de93948282a6ecad572683af41d9531ea4551f2dc7bbc2"),
    }; }
}
