// Tests execute the exact extracted upstream/candidate generate body and
// upstream finalizer. Processor/model dependencies are fakes: no numeric claim.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace geniex {
using Clock = std::chrono::high_resolution_clock;
#include "generate_result.inc"
static std::vector<std::string> logs;
static void capture_error(const char* format) { logs.emplace_back(format); }
static void capture_error(const char* format, const char* message) {
    logs.emplace_back(std::string(format) + " | " + message);
}
#define GENIEX_LOG_ERROR(...) capture_error(__VA_ARGS__)

struct Tokenizer { std::string decode_token(int32_t token) { return token == 42 ? "B" : "?"; } };
struct GenerationConfig {
    int64_t max_tokens = 8;
    std::string grammar_str;
    Tokenizer* tokenizer = nullptr;
};
struct BatchFeatures { std::vector<int32_t> input_ids{11, 12}; };
struct VLMInput { int pixel_data = 0; };
static int toPixelData(const BatchFeatures&) { return 0; }
struct PromptTooLongError : std::runtime_error { using std::runtime_error::runtime_error; };
struct ContextLengthExceededError : std::runtime_error { using std::runtime_error::runtime_error; };
struct VisionProcessor {
    bool fail = false;
    BatchFeatures process(const std::string&, const std::vector<std::string>&) {
        if (fail) throw std::runtime_error("processor failure");
        return {};
    }
};
struct VLMModel {
    enum Failure { NONE, STANDARD, UNKNOWN, PROMPT, CONTEXT, PARTIAL, LENGTH } failure = NONE;
    int calls = 0;
    size_t nPast() const { return 0; }
    double lastMediaMs() const { return 4.0; }
    std::vector<int32_t> generate(const std::vector<int32_t>& tokens, const VLMInput&,
                                 const GenerationConfig& cfg, std::function<bool(int32_t)> cb) {
        ++calls;
        if (tokens != std::vector<int32_t>({151643, 11, 12}) || !cfg.tokenizer)
            throw std::logic_error("unexpected preparation or missing tokenizer");
        if (failure == STANDARD) throw std::runtime_error("grammar init failed");
        if (failure == UNKNOWN) throw 17;
        if (failure == PROMPT) throw PromptTooLongError("prompt too long");
        if (failure == CONTEXT) throw ContextLengthExceededError("context exceeded");
        if (failure == LENGTH) {
            std::vector<int32_t> result;
            for (int64_t i = 0; i < cfg.max_tokens; ++i) {
                result.push_back(42);
                if (!cb(42)) break;
            }
            return result;
        }
        (void)cb(42);
        if (failure == PARTIAL) throw std::runtime_error("later grammar failure");
        return {42};
    }
};
class VLMPipeline {
public:
    struct Impl {
        std::unique_ptr<VLMModel> model = std::make_unique<VLMModel>();
        std::unique_ptr<VisionProcessor> processor = std::make_unique<VisionProcessor>();
        Tokenizer* tokenizer = nullptr;
        bool ready = true;
        int32_t bos_token_id = 151643;
    };
    Tokenizer tokenizer;
    std::unique_ptr<Impl> impl_ = std::make_unique<Impl>();
    VLMPipeline() { impl_->tokenizer = &tokenizer; }
    GenerateResult generate(const std::string&, const std::vector<std::string>&,
                            const GenerationConfig&, std::function<bool(const char*)>);
};
#include "finalize_generate_result.inc"
#include "pipeline_generate.inc"
} // namespace geniex

static void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
static int failed = 0, passed = 0;
template<class F> static void test(const char* name, F fn) {
    geniex::logs.clear();
    try { fn(); ++passed; std::printf("{\"test\":\"%s\",\"pass\":true}\n", name); }
    catch (const std::exception& e) {
        ++failed; std::printf("{\"test\":\"%s\",\"pass\":false,\"reason\":\"%s\"}\n", name, e.what());
    } catch (...) { ++failed; std::printf("{\"test\":\"%s\",\"pass\":false,\"reason\":\"escaped nonstandard exception\"}\n", name); }
}
static geniex::GenerateResult run(geniex::VLMPipeline& p, bool grammar,
                                 std::function<bool(const char*)> cb = nullptr) {
    geniex::GenerationConfig cfg;
    if (grammar) cfg.grammar_str = "root ::= \"B\"";
    return p.generate("prompt", {}, cfg, std::move(cb));
}
int main() {
    using namespace geniex;
    test("valid_grammar_unchanged", [] { VLMPipeline p; auto r=run(p,true); check(r.full_text=="B"&&r.stop_reason=="eos"&&r.generated_tokens==2&&r.prompt_tokens==3&&r.media_ms==4&&p.impl_->model->calls==1,"valid grammar changed"); });
    test("valid_no_grammar_unchanged", [] { VLMPipeline p; auto r=run(p,false); check(r.full_text=="B"&&r.stop_reason=="eos"&&r.generated_tokens==2&&logs.empty(),"no grammar changed"); });
    test("normal_length_preserved", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::LENGTH;auto r=run(p,true);check(r.stop_reason=="length"&&r.full_text=="BBBBBBBB"&&r.generated_tokens==8,"length behavior changed"); });
    test("requested_grammar_standard_error_result", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::STANDARD;auto r=run(p,true);check(r.stop_reason=="error"&&r.full_text.empty()&&r.generated_tokens==0&&p.impl_->model->calls==1&&!logs.empty()&&logs[0].find("grammar init failed")!=std::string::npos,"grammar exception not explicit error"); });
    test("requested_grammar_nonstandard_error_result", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::UNKNOWN;auto r=run(p,true);check(r.stop_reason=="error"&&r.full_text.empty()&&r.generated_tokens==0&&p.impl_->model->calls==1&&!logs.empty(),"nonstandard error not explicit"); });
    test("no_grammar_standard_still_propagates", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::STANDARD;bool caught=false;try{(void)run(p,false);}catch(const std::runtime_error&){caught=true;}check(caught&&logs.empty(),"no grammar standard behavior changed"); });
    test("no_grammar_unknown_still_propagates", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::UNKNOWN;bool caught=false;try{(void)run(p,false);}catch(int v){caught=v==17;}check(caught&&logs.empty(),"no grammar unknown behavior changed"); });
    test("prompt_too_long_priority_preserved", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::PROMPT;auto r=run(p,true);check(r.stop_reason=="prompt_too_long"&&r.generated_tokens==0&&logs.empty(),"prompt classification changed"); });
    test("context_length_priority_preserved", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::CONTEXT;auto r=run(p,true);check(r.stop_reason=="context_length"&&r.generated_tokens==0&&logs.empty(),"context classification changed"); });
    test("no_grammar_context_preserved", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::CONTEXT;check(run(p,false).stop_reason=="context_length","no grammar context changed"); });
    test("partial_output_is_error_not_eos", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::PARTIAL;auto r=run(p,true);check(r.stop_reason=="error"&&r.full_text=="B"&&r.generated_tokens==1&&p.impl_->model->calls==1,"partial output incorrectly success/EOS/retried"); });
    test("invalid_then_next_request_is_not_downgraded", [] { VLMPipeline p;p.impl_->model->failure=VLMModel::STANDARD;check(run(p,true).stop_reason=="error","first must error");p.impl_->model->failure=VLMModel::NONE;check(run(p,true).stop_reason=="eos"&&p.impl_->model->calls==2,"next request changed"); });
    test("callback_stop_preserved", [] { VLMPipeline p;auto r=run(p,true,[](const char*){return false;});check(r.stop_reason=="user"&&r.generated_tokens==1,"cancel result changed"); });
    test("processor_failure_grammar_preserved", [] { VLMPipeline p;p.impl_->processor->fail=true;check(run(p,true).stop_reason=="error"&&p.impl_->model->calls==0,"processor error changed"); });
    test("processor_failure_no_grammar_preserved", [] { VLMPipeline p;p.impl_->processor->fail=true;check(run(p,false).stop_reason=="error"&&p.impl_->model->calls==0,"processor no-grammar error changed"); });
    test("not_ready_preserved", [] { VLMPipeline p;p.impl_->ready=false;check(run(p,true).stop_reason=="error"&&p.impl_->model->calls==0,"not-ready changed"); });
    std::printf("{\"passed\":%d,\"failed\":%d}\n",passed,failed);
    return failed?1:0;
}
