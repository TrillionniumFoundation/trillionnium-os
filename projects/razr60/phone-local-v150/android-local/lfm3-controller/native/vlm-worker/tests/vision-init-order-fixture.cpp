// Host lifecycle double. The production statements are inserted without editing them.
// This executes ordering and failure paths, not an OpenCL kernel or a model.
#include "mtmd.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

struct ggml_backend_device { bool initialized = false; };
struct ggml_backend_buffer_type { ggml_backend_device * device; };
struct mtmd_context { bool supports_vision = true; };
struct llama_model {};
static ggml_backend_device selected_gpu;
static ggml_backend_buffer_type selected_buffer{&selected_gpu};
static mtmd_context vision_context;
static llama_model language_model;
static constexpr uint64_t allocation_limit = UINT64_C(0x100000123);
struct State {
    int scenario = 0;
    unsigned init = 0, support = 0, currentness = 0, buffer = 0, metric = 0;
    bool explicit_gpu = false;
    std::vector<std::string> events;
};
static State state;
static unsigned checks = 0;
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL line %d\n", __LINE__); std::exit(1); } } while (0)
static void need(bool value, const char * message) { if (!value) throw std::runtime_error(message); }
struct Request {
    void check() {
        ++state.currentness; state.events.push_back("currentness");
        if (state.scenario == 3) throw std::runtime_error("request cancelled");
    }
};
struct Resources { llama_model * model = &language_model; mtmd_context * vision = nullptr; };

mtmd_context_params mtmd_context_params_default() { return {}; }
mtmd_context * mtmd_init_from_file(const char * path, const llama_model * model, mtmd_context_params params) {
    ++state.init; state.events.push_back("init");
    state.explicit_gpu = params.use_gpu && params.device == &selected_gpu;
    need(state.explicit_gpu && model == &language_model && std::string(path) == "/held-projector-fd",
         "wrong model/projector/explicit GPU");
    if (state.scenario == 1) return nullptr;
    selected_gpu.initialized = true;
    vision_context.supports_vision = state.scenario != 2;
    return &vision_context;
}
bool mtmd_support_vision(mtmd_context * context) {
    ++state.support; state.events.push_back("support");
    need(context == &vision_context, "wrong vision context");
    return context->supports_vision;
}
ggml_backend_buffer_type_t ggml_backend_dev_buffer_type(ggml_backend_dev_t device) {
    ++state.buffer; state.events.push_back("buffer");
    need(device == &selected_gpu, "wrong metric GPU");
    return &selected_buffer;
}
size_t ggml_backend_buft_get_max_size(ggml_backend_buffer_type_t buffer) {
    ++state.metric; state.events.push_back("metric");
    need(buffer == &selected_buffer && buffer->device->initialized, "metric before backend initialization");
    return static_cast<size_t>(allocation_limit);
}

struct Outcome { std::map<std::string, uint64_t> receipt; std::string error; };
static Outcome execute(int scenario, bool early_metric_control) {
    state = State{}; state.scenario = scenario; selected_gpu.initialized = false;
    Outcome result;
    auto & receipt = result.receipt;
    ggml_backend_dev_t gpu = &selected_gpu;
    Resources res; Request r;
    const std::string projector_fd = "/held-projector-fd";
    @PARAMETERS@
    try {
        if (early_metric_control) {
@EARLY_METRIC_CONTROL@
        } else {
@PRODUCTION_STATEMENTS@
        }
    } catch (const std::runtime_error & error) { result.error = error.what(); }
    return result;
}

int main() {
    auto success = execute(0, false);
    CHECK(success.error.empty());
    CHECK(state.init == 1 && state.support == 1 && state.currentness == 1);
    CHECK(state.buffer == 1 && state.metric == 1);
    CHECK(state.explicit_gpu);
    CHECK(state.events == std::vector<std::string>({"init", "support", "currentness", "buffer", "metric"}));
    CHECK(success.receipt.size() == 1 && success.receipt.at("vision_max_allocation_bytes") == allocation_limit);

    auto failed_init = execute(1, false);
    CHECK(failed_init.error == "GPUOpenCL vision load failed; fallback forbidden");
    CHECK(state.init == 1 && state.support == 0 && state.currentness == 0);
    CHECK(state.buffer == 0 && state.metric == 0 && failed_init.receipt.empty());
    CHECK(state.events == std::vector<std::string>({"init"}));

    auto unsupported = execute(2, false);
    CHECK(unsupported.error == "GPUOpenCL vision load failed; fallback forbidden");
    CHECK(state.init == 1 && state.support == 1 && state.currentness == 0);
    CHECK(state.buffer == 0 && state.metric == 0 && unsupported.receipt.empty());
    CHECK(state.events == std::vector<std::string>({"init", "support"}));

    auto cancelled = execute(3, false);
    CHECK(cancelled.error == "request cancelled");
    CHECK(state.init == 1 && state.support == 1 && state.currentness == 1);
    CHECK(state.buffer == 0 && state.metric == 0 && cancelled.receipt.empty());
    CHECK(state.events == std::vector<std::string>({"init", "support", "currentness"}));

    auto regression = execute(0, true);
    CHECK(regression.error == "metric before backend initialization");
    CHECK(state.init == 0 && state.support == 0 && state.currentness == 0);
    CHECK(state.buffer == 1 && state.metric == 1);
    CHECK(regression.receipt.empty());
    CHECK(state.events == std::vector<std::string>({"buffer", "metric"}));
    std::printf("{\"schema\":\"hepta.vlm.vision-init-order-host.v1\",\"passed\":true,\"cases\":5,\"checks\":%u,\"production_statements_executed\":true,\"early_metric_control_rejected\":true,\"phone_contacted\":false,\"model_inference_performed\":false}\n", checks);
}
