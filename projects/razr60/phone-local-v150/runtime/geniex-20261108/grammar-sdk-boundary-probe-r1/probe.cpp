// Diagnostic only. A fake IVlm calls the unchanged proc Grammar constructor.
// No model is created, no geniex_init call is made, and no QNN is loaded.
#include "IVlm.h"
#include "geniex-proc/sampler.h"
#include "geniex-proc/tokenizer.h"
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <sys/resource.h>
#include <unistd.h>

static unsigned callback_count = 0;
static bool callback(const char*, void*) { ++callback_count; return true; }

class GrammarBackend final : public geniex::IVlm {
    geniex::Tokenizer& tokenizer_;
    std::string grammar_;
    bool contain_;
    int32_t construct() {
        std::fprintf(stderr, "fake-backend: entering original proc Grammar constructor\n");
        geniex::Grammar parsed(grammar_, tokenizer_, "root");
        std::fprintf(stderr, "fake-backend: valid Grammar constructed; no tokens generated\n");
        return GENIEX_SUCCESS;
    }
public:
    GrammarBackend(geniex::Tokenizer& tokenizer, bool valid, bool contain)
        : tokenizer_(tokenizer), grammar_(valid ? "root ::= \"B\"\n" : "root ::= \"unterminated\n"),
          contain_(contain) {}
    int32_t create(const geniex_VlmCreateInput*) override { return GENIEX_ERROR_COMMON_PARAM_NOT_SUPPORTED; }
    int32_t reset() override { return GENIEX_ERROR_COMMON_PARAM_NOT_SUPPORTED; }
    int32_t apply_chat_template(const geniex_VlmApplyChatTemplateInput*, geniex_VlmApplyChatTemplateOutput*) override {
        return GENIEX_ERROR_COMMON_PARAM_NOT_SUPPORTED;
    }
    int32_t generate(const geniex_VlmGenerateInput*, geniex_VlmGenerateOutput*) override {
        if (!contain_) return construct();
        try { return construct(); }
        catch (const std::exception& error) {
            std::fprintf(stderr, "fake-backend: caught std::exception locally: %s\n", error.what());
            return GENIEX_ERROR_VLM_GENERATION_FAILED;
        } catch (...) {
            std::fprintf(stderr, "fake-backend: caught unknown exception locally\n");
            return GENIEX_ERROR_VLM_GENERATION_FAILED;
        }
    }
};

extern "C" __attribute__((visibility("default")))
int grammar_sdk_boundary_probe(int argc, char** argv) {
    const rlimit no_core{0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return 65;
    alarm(15);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc != 4) return 64;
    const std::string mode(argv[2]);
    const bool direct = mode == "direct-invalid";
    const bool valid = mode == "sdk-valid";
    const bool contained = mode == "sdk-contained";
    if (!direct && !valid && !contained && mode != "sdk-invalid") return 64;
    const bool with_callback = std::strcmp(argv[3], "callback") == 0;
    if (!with_callback && std::strcmp(argv[3], "no-callback") != 0) return 64;
    try {
        std::fprintf(stderr, "boundary-probe: loading tokenizer only\n");
        auto tokenizer = geniex::Tokenizer::from_file(argv[1]);
        if (!tokenizer) return 68;
        GrammarBackend backend(*tokenizer, valid, contained);
        geniex_VlmGenerateInput input{};
        input.prompt_utf8 = "diagnostic only";
        input.on_token = with_callback ? callback : nullptr;
        geniex_VlmGenerateOutput output{};
        std::fprintf(stderr, "boundary-probe: path=%s callback=%s\n", mode.c_str(), with_callback ? "true" : "false");
        try {
            auto* interface_handle = static_cast<geniex::IVlm*>(&backend);
            const int32_t rc = direct ? backend.generate(&input, &output)
                : geniex_vlm_generate(reinterpret_cast<geniex_VLM*>(interface_handle), &input, &output);
            std::fprintf(stderr, "boundary-probe: returned sdk_rc=%d full_text_null=%s callbacks=%u\n",
                         rc, output.full_text == nullptr ? "true" : "false", callback_count);
            const bool had_output = output.full_text != nullptr;
            if (output.full_text) geniex_free(output.full_text);
            if (callback_count != 0 || had_output) return 69;
            if (valid) return rc == GENIEX_SUCCESS ? 0 : 40;
            if (contained) return rc == GENIEX_ERROR_VLM_GENERATION_FAILED ? 22 : 41;
            return rc == GENIEX_ERROR_COMMON_UNKNOWN ? 23 : 42;
        } catch (const std::exception& error) {
            std::fprintf(stderr, "boundary-probe: exception escaped %s and caught by caller std::exception: %s\n",
                         direct ? "fake backend" : "original SDK C ABI", error.what());
            return direct ? 10 : 30;
        } catch (...) {
            std::fprintf(stderr, "boundary-probe: exception escaped %s and caught by caller catch-all\n",
                         direct ? "fake backend" : "original SDK C ABI");
            return direct ? 11 : 31;
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "boundary-probe: setup exception: %s\n", error.what());
        return 20;
    } catch (...) {
        std::fprintf(stderr, "boundary-probe: setup unknown exception\n");
        return 21;
    }
}
#ifndef GRAMMAR_BOUNDARY_PROBE_DSO
int main(int argc, char** argv) { return grammar_sdk_boundary_probe(argc, argv); }
#endif
