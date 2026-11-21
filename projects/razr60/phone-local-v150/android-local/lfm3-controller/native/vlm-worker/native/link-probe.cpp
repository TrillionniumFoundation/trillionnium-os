#include "llama.h"
#include "ggml-backend.h"
#include "mtmd.h"
#include "mtmd-helper.h"
#include "common/chat.h"
#include <cstdio>

// Never run a model: this translation unit proves the matching public C and
// C++ API can be linked against the exact packaged Android libraries.
int main(int argc, char **argv) {
    if (argc != 99) return 0;
    ggml_backend_load_all_from_path(argv[1]);
    ggml_backend_dev_t devices[] = { ggml_backend_dev_by_name("HTP0"), nullptr };
    llama_model_params mp = llama_model_default_params();
    mp.devices = devices;
    mp.n_gpu_layers = 999;
    auto *model = llama_model_load_from_file(argv[2], mp);
    auto *ctx = llama_init_from_model(model, llama_context_default_params());
    auto vp = mtmd_context_params_default();
    vp.use_gpu = true;
    vp.device = ggml_backend_dev_by_name("GPUOpenCL");
    auto *vision = mtmd_init_from_file(argv[3], model, vp);
    auto bitmap = mtmd_helper_bitmap_init_from_buf(vision,
        reinterpret_cast<const unsigned char *>("x"), 1, false,
        mtmd_helper_init_opt_default());
    auto templates = common_chat_templates_init(model, "");
    common_chat_templates_inputs inputs;
    inputs.enable_thinking = false;
    common_chat_msg msg;
    msg.role = "user";
    msg.content_parts = {{"media_marker", mtmd_default_marker()}, {"text", "observe"}};
    inputs.messages.push_back(std::move(msg));
    auto chat = common_chat_templates_apply(templates.get(), inputs);
    std::string formatted = chat.prompt.str();
    auto *chunks = mtmd_input_chunks_init();
    const mtmd_bitmap *bitmaps[] = {bitmap.bitmap};
    mtmd_input_text txt{formatted.c_str(), formatted.size(), true, true};
    int rc = mtmd_tokenize(vision, chunks, &txt, bitmaps, 1);
    size_t n = mtmd_helper_get_n_tokens(chunks);
    llama_pos p = mtmd_helper_get_n_pos(chunks), np = 0;
    rc |= mtmd_helper_eval_chunks(vision, ctx, chunks, 0, 0, 256, true, &np);
    auto *chain = llama_sampler_chain_init(llama_sampler_chain_default_params());
    llama_sampler_chain_add(chain, llama_sampler_init_grammar(llama_model_get_vocab(model), "root ::= \"x\"", "root"));
    llama_sampler_chain_add(chain, llama_sampler_init_greedy());
    auto token = llama_sampler_sample(chain, ctx, -1);
    std::printf("%zu %d %d %d %d\n", n, p, np, rc, token);
    llama_sampler_free(chain);
    mtmd_input_chunks_free(chunks);
    mtmd_bitmap_free(bitmap.bitmap);
    mtmd_free(vision);
    llama_free(ctx);
    llama_model_free(model);
    return rc;
}
