# LFM3 context admission

The previous Qwen tokenizer.json pin and image-token allowance are removed. This contract is specific to the official SHA-pinned LFM3-1.7B-QAD-Q4_0.gguf selected by LocalRuntimeConfig.

Read-only research of the official GGUF metadata established tokenizer.ggml.model=gpt2, tokenizer.ggml.pre=lfm2, BOS 124894, EOS 124900, add_bos_token=false and add_eos_token=false. All 256 GPT-2 byte symbols are present in its 128,000-token vocabulary. The reference tokenizer.json has normalizer=null, regex Split plus ByteLevel(add_prefix_space=false), no continuation/end-of-word suffix, SHA-256 7e226e34bface23ccf6e495d157bf77186c1c30a7659880e1a8994db528c3701.

In the bundled llama.cpp 19cce6919992fdffd92e0ac152caaf1e2b8f254e, this tokenizer adds no space prefix or whitespace escaping. Starting from at most one symbol per UTF-8 byte, BPE merges and special-token recognition reduce token count. Native add_special=true can add at most one BOS and one EOS; this model enables neither. Therefore **actual rendered UTF-8 bytes + 2** is a conservative token upper bound. This is not a generic guarantee for arbitrary models or vision embeddings.

GenieX first applies this model's chat template with enable_thinking=false. The generated worker then bounds the actual formatted bytes, including role and empty-think tags, and requires:

```
formatted_utf8_bytes + 2 + requested_generation_tokens + 256 <= configured_context
```

A failure records formatted_prompt_exceeds_fixed_context before generation. There is no truncation/context shift on an admitted request. The app validates this bound in the native receipt before using output. The SDK profile.prompt_tokens is not used as an exact full-context count: it may only describe uncached prefill tokens.

The controller's earlier projection budget uses UTF-8 bytes of system/data/unchanged owner text plus a conservative 512-byte template allowance. It reduces nodes/apps/history to fit. The native check on the real rendered template remains the final bound if this earlier estimate underestimates formatting. Java writes StandardCharsets.UTF_8 files; this path does not use JNI modified UTF-8. Invalid surrogate sequences and NUL are rejected.

Sources reviewed at pinned revisions:

- https://huggingface.co/LiquidAI/LFM3-1.7B-GGUF/blob/main/LFM3-1.7B-QAD-Q4_0.gguf
- https://huggingface.co/LiquidAI/LFM3-1.7B/blob/main/tokenizer.json
- https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/src/llama-vocab.cpp
- https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/models/templates/LFM3.jinja
- https://github.com/qualcomm/GenieX/blob/v0.10.0/sdk/plugins/llama_cpp/src/llm.cpp
