void finalize_generate_result(GenerateResult& result, std::ostringstream& full_text, int64_t generated_tokens,
    Clock::time_point t_start, Clock::time_point t_first_token, Clock::time_point t_end, bool got_first,
    const char* stop_reason) {
    result.full_text = full_text.str();

    // Align with Genie's `num-generated-tokens`, which counts the terminating EOS
    // sample. The decode loop stops before emitting EOS into the text, so add it
    // back to the reported count (not to full_text) when generation ended on EOS.
    const bool ended_on_eos = stop_reason != nullptr && std::strcmp(stop_reason, "eos") == 0;
    result.generated_tokens = generated_tokens + (ended_on_eos ? 1 : 0);

    // Corner Case: First sample is EOS, the callback never fires, so got_first stays false and ttft
    // would be 0 though prefill ran. Use t_end as first-token time (ttft = prefill,
    // decode = 0). Only for "eos"; other stop reasons have no valid timing.
    const bool first_sample_eos = !got_first && ended_on_eos;
    if (got_first || first_sample_eos) {
        if (first_sample_eos) t_first_token = t_end;
        result.ttft_ms   = std::chrono::duration<double, std::milli>(t_first_token - t_start).count();
        result.decode_ms = std::chrono::duration<double, std::milli>(t_end - t_first_token).count();

        // Genie divides the EOS-inclusive token count by the decode window.
        result.tokens_per_second = result.decode_ms > 0.0 ? result.generated_tokens / (result.decode_ms / 1000.0) : 0.0;
    }
    result.stop_reason = stop_reason;
}
