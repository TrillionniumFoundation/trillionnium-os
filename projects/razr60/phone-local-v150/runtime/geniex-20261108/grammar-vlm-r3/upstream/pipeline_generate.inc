GenerateResult VLMPipeline::generate(const std::string& formatted_prompt, const std::vector<std::string>& image_paths,
    const GenerationConfig& gen_cfg, std::function<bool(const char*)> on_token) {
    GenerateResult result;
    if (!impl_->ready || !impl_->model || !impl_->processor || !impl_->tokenizer) {
        result.stop_reason = "error";
        return result;
    }

    VLMInput             vlm_input;
    std::vector<int32_t> prompt_tokens;

    try {
        BatchFeatures bf     = impl_->processor->process(formatted_prompt, image_paths);
        vlm_input.pixel_data = toPixelData(bf);
        prompt_tokens.assign(bf.input_ids.cbegin(), bf.input_ids.cend());
    } catch (...) {
        result.stop_reason = "error";
        return result;
    }

    // Prepend BOS only on the first turn
    if (impl_->bos_token_id >= 0 && impl_->model->nPast() == 0 &&
        (prompt_tokens.empty() || prompt_tokens.front() != impl_->bos_token_id)) {
        prompt_tokens.insert(prompt_tokens.begin(), impl_->bos_token_id);
    }

    result.prompt_tokens = static_cast<int64_t>(prompt_tokens.size());

    // Inject the tokenizer; LLMModel needs it for grammar/EOG resolution.
    GenerationConfig effective_cfg = gen_cfg;
    effective_cfg.tokenizer        = impl_->tokenizer;

    auto              t_start = Clock::now();
    Clock::time_point t_first_token;
    bool              got_first    = false;
    bool              user_stopped = false;

    std::ostringstream full_text;
    // Counted inside the callback so the partial total is correct even if the
    // model throws mid-decode (the returned vector is destroyed during unwind).
    int64_t streamed_tokens = 0;

    auto on_each_token = [&](int32_t tok) -> bool {
        if (!got_first) {
            t_first_token = Clock::now();
            got_first     = true;
        }
        std::string piece = impl_->tokenizer->decode_token(tok);
        full_text << piece;
        ++streamed_tokens;
        if (on_token && !piece.empty()) {
            if (!on_token(piece.c_str())) {
                user_stopped = true;
                return false;
            }
        }
        return !user_stopped;
    };

    try {
        auto output_tokens = impl_->model->generate(prompt_tokens, vlm_input, effective_cfg, on_each_token);
        auto t_end         = Clock::now();

        const int64_t total  = static_cast<int64_t>(output_tokens.size());
        const char*   reason = user_stopped ? "user" : (total >= gen_cfg.max_tokens ? "length" : "eos");
        finalize_generate_result(result, full_text, total, t_start, t_first_token, t_end, got_first, reason);
        result.media_ms = impl_->model->lastMediaMs();
        return result;
    } catch (const PromptTooLongError&) {
        const auto t_end = Clock::now();
        finalize_generate_result(
            result, full_text, streamed_tokens, t_start, t_first_token, t_end, got_first, "prompt_too_long");
        return result;
    } catch (const ContextLengthExceededError&) {
        const auto t_end = Clock::now();
        finalize_generate_result(
            result, full_text, streamed_tokens, t_start, t_first_token, t_end, got_first, "context_length");
        return result;
    }
}
