#pragma once
#include <cstdint>
struct ModelPin { const char *name; std::uint64_t size; const char *sha; };
static constexpr const char *MODEL_REPO = "fengerhu1/MobiMind-1.5-2B-W8A8-0717";
static constexpr const char *MODEL_REVISION = "f02848b6b7796988ea95df8f78a7b38bd71e2a90";
static constexpr const char *MNN_REVISION = "bce7456ce60b5e51b4d3b357f303515860353d8c";
static constexpr ModelPin MODEL_PINS[] = {
    {"README.md", 1029ULL, "52bd50ac9e33e6c87ce604ee1ae919d8193c85c9f5a2e338c407dc0d372fc36b"},
    {"config.json", 634ULL, "6fa0f3c99710b93415a6c7e8adf7e5d03e45c85094e75ff8974ad2f76b0c59b8"},
    {"configuration.json", 49ULL, "8fbd3c45576d536e5953c933bf7399d0ea57184032b4a98559461e1b285d74a8"},
    {"embeddings_bf16.bin", 622329856ULL, "b4f4b0a21e9b080729b3de7153b5f29f956e08c5d440c7d2fe4a8258c31178c9"},
    {"export_args.json", 1347ULL, "48bcffba4773ab9486fe204f7955b42c6ac8133fd79cae81ca9794e8e0e4af7c"},
    {"llm.mnn", 508712ULL, "176185b5b97c63e3100308f05d2cf31a192352bee0527f29fc6a83a884291297"},
    {"llm.mnn.weight", 2120738968ULL, "9b550448df562f08efb67b20054579b94e2d730c464f802d2908ac6456ac6cc7"},
    {"llm_config.json", 6056ULL, "8cbada58b4f5885e78ac6107458f4075a9dadcd12611ad7bb24af5b1f09c0119"},
    {"tokenizer.mtok", 4096835ULL, "d646d5bff3339247947ad3a0cf317fe2be609f789684db9048b2174a84a5d656"},
    {"visual.mnn", 5238472ULL, "0ecc507e46773533f7a93703adf1d416d5c6da7400e3f687eb366ce65a2d4c74"},
    {"visual.mnn.weight", 526865248ULL, "2620be5060322e9c56de93948282a6ecad572683af41d9531ea4551f2dc7bbc2"},
};
