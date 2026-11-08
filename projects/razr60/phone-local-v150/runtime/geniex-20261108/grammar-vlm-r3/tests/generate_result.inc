struct GenerateResult {
    std::string full_text;
    double      ttft_ms           = 0.0;  // time-to-first-token
    double      media_ms          = 0.0;  // vision/audio encoder time (VLM only; 0 for text)
    double      decode_ms         = 0.0;  // decode phase wall time
    int64_t     prompt_tokens     = 0;    // text + media tokens
    int64_t     generated_tokens  = 0;
    double      tokens_per_second = 0.0;
    std::string stop_reason;  // "eos" | "length" | "user" | "stop_sequence" | "context_length"
};
