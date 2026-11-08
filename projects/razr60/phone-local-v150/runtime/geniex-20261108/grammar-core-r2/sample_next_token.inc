int32_t LLMModel::sampleNextToken(size_t phase, size_t token_offset) {
    std::vector<float> logits;
    readLastLogits(phase, token_offset, logits);

    if (sampler_) {
        // The pinned proc Sampler::sample already accepts the selected token.
        // A second accept would advance the output grammar twice. Restrict this
        // change to a validated grammar request; preserve upstream no-grammar
        // penalty/history behavior for this narrowly scoped repair.
        const int32_t tok = sampler_->sample(logits);
        if (sampler_cfg_.grammar_str.empty()) {
            sampler_->accept(tok);
        }
        return tok;
    }

    // Greedy fast path is unchanged when sampling is disabled.
    return static_cast<int32_t>(std::max_element(logits.begin(), logits.end()) - logits.begin());
}
