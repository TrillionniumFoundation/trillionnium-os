// Exact candidate methods are included below. Processor ABI fakes reproduce
// the pinned sample()->accept() behavior; no model or numerical SDK is used.
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace geniex {
constexpr int32_t EOG = 151645;
constexpr int32_t OUTPUT_B = 66;
constexpr int32_t OUTPUT_C = 67;
constexpr int32_t OTHER_A = 65;
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
        if (text != "BC" || root != "root") throw std::runtime_error("invalid grammar");
        events.push_back("grammar-created");
    }
    bool allows(int32_t token) const {
        const std::vector<int32_t> accepted{OUTPUT_B, OUTPUT_C, EOG};
        return output.size() < accepted.size() && token == accepted[output.size()];
    }
    void accept(int32_t token) {
        if (!allows(token)) throw std::runtime_error("grammar rejected token");
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
    void accept(int32_t token) {
        if (grammar) grammar->accept(token);
        history.push_back(token);
    }
    void init(const std::vector<int32_t>& input) {
        events.push_back("prompt-init");
        for (auto id : input) accept(id);
    }
    int32_t sample(const std::vector<float>& logits) {
        int32_t best = -1;
        for (size_t index = 0; index < logits.size(); ++index) {
            const auto token = static_cast<int32_t>(index);
            if (grammar && !grammar->allows(token)) continue;
            if (best < 0 || logits[index] > logits[static_cast<size_t>(best)]) best = token;
        }
        if (best < 0) throw std::runtime_error("no allowed output token");
        // This is critical pinned semantics: sample() accepts internally.
        accept(best);
        return best;
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
    std::vector<float> logits = std::vector<float>(static_cast<size_t>(EOG) + 1, -1);
    std::vector<std::pair<size_t, size_t>> reads;
    void readLastLogits(size_t phase, size_t offset, std::vector<float>& output) {
        reads.emplace_back(phase, offset);
        output = logits;
    }
    void prepareSampler(const GenerationConfig&, const std::vector<int32_t>&);
    int32_t sampleNextToken(size_t, size_t);
};

#include "../prepare_sampler.inc"
#include "../sample_next_token.inc"
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
    cfg.grammar_str = "BC";
    cfg.tokenizer = &tokenizer;
    LLMModel model;
    // The prompt preference contradicts the grammar's first output token.
    model.logits[OTHER_A] = 100;
    model.prepareSampler(cfg, {11, EOG, 22});
    expect(model.sampler_->history == std::vector<int32_t>({11, EOG, 22}), "prompt history omitted");
    expect(model.sampler_->grammar && model.sampler_->grammar->output.empty(), "prompt advanced grammar");
    expect(make_sampler_grammar_inputs == std::vector<std::string>({""}), "construction received grammar");
    expect(events == std::vector<std::string>({"grammar-created", "grammar-detached", "prompt-init", "grammar-attached"}), "setup ordering differs");
    const auto first_grammar = model.sampler_->grammar->serial;
    auto* first_sampler = model.sampler_.get();

    expect(model.sampleNextToken(0, 17) == OUTPUT_B, "first sampled token unconstrained");
    expect(model.sampler_->history == std::vector<int32_t>({11, EOG, 22, OUTPUT_B}), "first token accepted twice");
    expect(model.sampleNextToken(1, 0) == OUTPUT_C, "subsequent sampled token differs");
    expect(model.sampleNextToken(1, 0) == EOG, "EOG not accepted at grammar end");
    expect(model.sampler_->grammar->output == std::vector<int32_t>({OUTPUT_B, OUTPUT_C, EOG}), "output grammar advanced incorrectly");
    expect(model.sampler_->history == std::vector<int32_t>({11, EOG, 22, OUTPUT_B, OUTPUT_C, EOG}), "generated history not exactly once");
    expect(model.reads == std::vector<std::pair<size_t,size_t>>({{0,17},{1,0},{1,0}}), "logit selection phase/offset changed");

    events.clear();
    model.prepareSampler(cfg, {33, EOG});
    expect(model.sampler_.get() == first_sampler && sampler_creations == 1, "cache reuse discarded history");
    expect(model.sampler_->history == std::vector<int32_t>({11,EOG,22,OUTPUT_B,OUTPUT_C,EOG,33,EOG}), "multiturn prompt history differs");
    expect(model.sampler_->grammar->serial != first_grammar && model.sampler_->grammar->output.empty(), "multiturn grammar not fresh");
    expect(model.sampleNextToken(0, 0) == OUTPUT_B, "next-turn first token differs");
    expect(model.sampleNextToken(1, 0) == OUTPUT_C, "next-turn subsequent token differs");
    expect(model.sampleNextToken(1, 0) == EOG, "next-turn EOG differs");
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
    auto disabled = cfg; disabled.enable_sampling = false;
    expect_failure([&] { model.prepareSampler(disabled, {}); }, "grammar ignored when sampling disabled");
    expect(model.sampler_->history == before_bad_history, "rejected configuration mutated history");

    GenerationConfig plain;
    model.prepareSampler(plain, {55, EOG});
    expect(!model.sampler_->grammar, "no-grammar path retained a grammar");
    expect(model.sampleNextToken(0, 0) == OTHER_A, "no-grammar sampled result changed");
    // Deliberately preserve the pinned upstream no-grammar double acceptance.
    expect(model.sampler_->history == std::vector<int32_t>({55,EOG,OTHER_A,OTHER_A}), "no-grammar history behavior changed");
    auto* plain_sampler = model.sampler_.get();
    model.prepareSampler(plain, {56});
    expect(model.sampler_.get() == plain_sampler && model.sampler_->history == std::vector<int32_t>({55,EOG,OTHER_A,OTHER_A,56}),
           "plain reuse history changed");
    plain.temperature = 0.25f;
    model.prepareSampler(plain, {57});
    expect(model.sampler_->history == std::vector<int32_t>({57}), "changed config did not rebuild like upstream");
    plain.enable_sampling = false;
    model.prepareSampler(plain, {58});
    expect(!model.sampler_ && !model.sampler_cfg_valid_, "disabled no-grammar behavior changed");
    expect(model.sampleNextToken(1, 4) == OTHER_A, "greedy no-sampler result changed");
    for (const auto& grammar : make_sampler_grammar_inputs) expect(grammar.empty(), "stock helper saw grammar");
    std::cout << "PASS: actual setup and sampleNextToken methods; prompt EOG isolation; first/subsequent/EOG "
                 "accepted once; next-turn/empty-prompt reset; invalid/missing grammar inputs fail; "
                 "no-grammar history and greedy behavior preserved\n";
}
