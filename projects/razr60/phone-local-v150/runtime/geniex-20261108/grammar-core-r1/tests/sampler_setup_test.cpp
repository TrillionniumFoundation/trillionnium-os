// Tests the exact replacement function included by the patch generator.
// Fakes replace the external processor ABI; this is not an NPU/numerical test.
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace geniex {
constexpr int32_t EOG = 151645;
constexpr int32_t OUTPUT_B = 66;
struct Tokenizer {};
struct GenerationConfig {
    bool enable_sampling = true;
    float temperature = 0;
    std::string grammar_str;
    std::string grammar_root = "root";
    Tokenizer* tokenizer = nullptr;
};
static std::vector<std::string> events;
static size_t grammar_serial = 0;
static size_t sampler_creations = 0;
static std::vector<std::string> make_sampler_grammar_inputs;

struct Grammar {
    size_t serial;
    std::vector<int32_t> output;
    Grammar(const std::string& text, Tokenizer&, const std::string& root) : serial(++grammar_serial) {
        if (text != "B" || root != "root") throw std::runtime_error("invalid grammar");
        events.push_back("grammar-created");
    }
    void accept(int32_t token) {
        if ((output.empty() && token != OUTPUT_B) ||
            (output.size() == 1 && token != EOG) || output.size() >= 2) {
            throw std::runtime_error("grammar rejected token");
        }
        output.push_back(token);
    }
};

struct Sampler {
    std::vector<int32_t> history;
    std::unique_ptr<Grammar> grammar;
    std::vector<int32_t> eog_tokens;
    void set_grammar(std::unique_ptr<Grammar> value) {
        events.push_back(value ? "grammar-attached" : "grammar-detached");
        grammar = std::move(value);
    }
    // Matches the pinned proc public behavior: init invokes the same acceptance
    // path as generation, so any attached grammar would see every prompt ID.
    void accept(int32_t token) {
        if (grammar) grammar->accept(token);
        history.push_back(token);
    }
    void init(const std::vector<int32_t>& input) {
        events.push_back("prompt-init");
        for (auto id : input) accept(id);
    }
};

static bool samplerConfigEqual(const GenerationConfig& a, const GenerationConfig& b) {
    return a.enable_sampling == b.enable_sampling && a.temperature == b.temperature &&
           a.grammar_str == b.grammar_str && a.grammar_root == b.grammar_root;
}

static std::unique_ptr<Sampler> makeSampler(const GenerationConfig& cfg, const std::vector<int32_t>& eog) {
    ++sampler_creations;
    make_sampler_grammar_inputs.push_back(cfg.grammar_str);
    auto value = std::make_unique<Sampler>();
    value->eog_tokens = eog;
    if (!cfg.grammar_str.empty()) {
        if (!cfg.tokenizer) throw std::runtime_error("fake stock helper requires tokenizer");
        value->set_grammar(std::make_unique<Grammar>(cfg.grammar_str, *cfg.tokenizer, cfg.grammar_root));
    }
    return value;
}

struct LLMModel {
    struct Spec { std::vector<int32_t> eos_token_ids{EOG}; } spec_;
    std::unique_ptr<Sampler> sampler_;
    bool sampler_cfg_valid_ = false;
    GenerationConfig sampler_cfg_;
    void prepareSampler(const GenerationConfig&, const std::vector<int32_t>&);
};

// This is also the sole replacement body read by prepare_patch.py.
#include "../prepare_sampler.inc"
}  // namespace geniex

static void expect(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

template<class F> static void expect_failure(F call, const char* message) {
    bool failed = false;
    try { call(); } catch (const std::exception&) { failed = true; }
    expect(failed, message);
}

int main() {
    using namespace geniex;
    Tokenizer tokenizer;
    GenerationConfig cfg;
    cfg.grammar_str = "B";
    cfg.tokenizer = &tokenizer;
    LLMModel model;

    model.prepareSampler(cfg, {11, EOG, 22});
    expect(model.sampler_->history == std::vector<int32_t>({11, EOG, 22}), "prompt history omitted");
    expect(model.sampler_->grammar && model.sampler_->grammar->output.empty(), "prompt advanced grammar");
    expect(make_sampler_grammar_inputs == std::vector<std::string>({""}), "construction received grammar");
    expect(events == std::vector<std::string>({"grammar-created", "grammar-detached", "prompt-init", "grammar-attached"}), "setup ordering differs");
    const auto first_grammar = model.sampler_->grammar->serial;
    auto* first_sampler = model.sampler_.get();
    model.sampler_->accept(OUTPUT_B);
    model.sampler_->accept(EOG);
    expect_failure([&] { model.sampler_->accept(OUTPUT_B); }, "output grammar did not constrain tokens");

    events.clear();
    model.prepareSampler(cfg, {33, EOG});
    expect(model.sampler_.get() == first_sampler && sampler_creations == 1, "unchanged config discarded history");
    expect(model.sampler_->history == std::vector<int32_t>({11, EOG, 22, OUTPUT_B, EOG, 33, EOG}), "multiturn penalty history differs");
    expect(model.sampler_->grammar->serial != first_grammar && model.sampler_->grammar->output.empty(), "multiturn grammar not reset");
    expect(events == std::vector<std::string>({"grammar-created", "grammar-detached", "prompt-init", "grammar-attached"}), "reuse ordering differs");

    model.sampler_->accept(OUTPUT_B);
    model.sampler_->accept(EOG);
    const auto second_grammar = model.sampler_->grammar->serial;
    const auto retained = model.sampler_->history;
    model.prepareSampler(cfg, {});
    expect(model.sampler_->history == retained && model.sampler_->grammar->output.empty() &&
           model.sampler_->grammar->serial != second_grammar, "empty prompt failed to reset grammar");

    const auto before_bad_history = model.sampler_->history;
    const auto before_bad_grammar = model.sampler_->grammar->serial;
    auto invalid = cfg; invalid.grammar_str = "invalid";
    expect_failure([&] { model.prepareSampler(invalid, {44, EOG}); }, "invalid grammar silently accepted");
    expect(model.sampler_->history == before_bad_history && model.sampler_->grammar->serial == before_bad_grammar,
           "invalid grammar changed old state");
    invalid = cfg; invalid.grammar_root = "missing-root";
    expect_failure([&] { model.prepareSampler(invalid, {EOG}); }, "invalid root silently accepted");
    invalid = cfg; invalid.tokenizer = nullptr;
    expect_failure([&] { model.prepareSampler(invalid, {EOG}); }, "missing tokenizer silently accepted");
    expect(model.sampler_->history == before_bad_history, "rejected configuration changed history");

    auto disabled = cfg; disabled.enable_sampling = false;
    expect_failure([&] { model.prepareSampler(disabled, {}); }, "grammar silently ignored when sampling disabled");
    expect(model.sampler_.get() == first_sampler, "rejected disabled grammar reset old sampler");

    GenerationConfig plain;
    model.prepareSampler(plain, {55, EOG});
    expect(!model.sampler_->grammar && model.sampler_->history == std::vector<int32_t>({55, EOG}), "plain generation changed");
    auto* plain_sampler = model.sampler_.get();
    model.prepareSampler(plain, {56});
    expect(model.sampler_.get() == plain_sampler && model.sampler_->history == std::vector<int32_t>({55, EOG, 56}),
           "plain multiturn history changed");
    plain.temperature = 0.25f;
    model.prepareSampler(plain, {57});
    expect(model.sampler_->history == std::vector<int32_t>({57}), "changed config did not rebuild like upstream");
    plain.enable_sampling = false;
    model.prepareSampler(plain, {58});
    expect(!model.sampler_ && !model.sampler_cfg_valid_, "disabled no-grammar behavior changed");
    for (const auto& grammar : make_sampler_grammar_inputs) expect(grammar.empty(), "stock helper saw grammar");
    std::cout << "PASS: prompt EOG isolation; generated-token constraints; multi-turn/empty-prompt grammar reset; "
                 "invalid grammar/root/missing tokenizer rejection; no-grammar reuse/config-change/disable behavior\n";
}
