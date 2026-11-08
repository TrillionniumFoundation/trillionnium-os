void LLMModel::prepareSampler(const GenerationConfig& gen_cfg, const std::vector<int32_t>& prompt_tokens) {
    // A requested output grammar must never silently become unconstrained output.
    if (!gen_cfg.grammar_str.empty() && !gen_cfg.enable_sampling) {
        throw std::invalid_argument("output grammar requires sampling to be enabled");
    }
    if (!gen_cfg.enable_sampling) {
        sampler_.reset();
        sampler_cfg_valid_ = false;
        return;
    }

    // Validate before changing existing sampler/history state. Exceptions from
    // Grammar are intentional failures; the old warn-and-continue path is not
    // used for a requested grammar in this setup.
    std::unique_ptr<Grammar> output_grammar;
    if (!gen_cfg.grammar_str.empty()) {
        if (!gen_cfg.tokenizer) {
            throw std::invalid_argument("output grammar requires a tokenizer");
        }
        output_grammar = std::make_unique<Grammar>(
            gen_cfg.grammar_str, *gen_cfg.tokenizer, gen_cfg.grammar_root);
    }

    // Preserve the upstream cache key and penalty/DRY history across turns.
    const bool can_reuse = sampler_ && sampler_cfg_valid_ && samplerConfigEqual(sampler_cfg_, gen_cfg);
    if (!can_reuse) {
        auto history_cfg = gen_cfg;
        history_cfg.grammar_str.clear();
        sampler_ = makeSampler(history_cfg, spec_.eos_token_ids);
        sampler_cfg_ = gen_cfg;
        sampler_cfg_valid_ = true;
    }

    // Prompt tokens, including chat EOG markers, seed penalties/history only.
    // The output grammar starts fresh for every response, including cache reuse
    // and empty incremental prompts; generated-token accept() is unchanged.
    sampler_->set_grammar(nullptr);
    if (!prompt_tokens.empty()) {
        sampler_->init(prompt_tokens);
    }
    if (output_grammar) {
        sampler_->set_grammar(std::move(output_grammar));
    }
}
