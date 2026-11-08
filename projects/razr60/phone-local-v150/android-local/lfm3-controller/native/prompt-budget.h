#ifndef HEPTA_LFM3_PROMPT_BUDGET_H
#define HEPTA_LFM3_PROMPT_BUDGET_H
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define HEPTA_MODEL_SHA256 "43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452"
#define HEPTA_RESERVED_TOKENS 256u
#define HEPTA_BOS_EOS_UPPER 2u

/* Valid only for the selected GGUF's verified byte-level BPE tokenizer.
 * All 256 byte symbols exist, normalizer/prefix-space are absent. Native
 * common_tokenize uses add_special=true, parse_special=true; at most one BOS
 * and one EOS can be inserted (the selected artifact enables neither).
 * This counts the actual formatted standard UTF-8, including role/think tags.
 */
typedef struct {
    bool checked, admitted;
    size_t formatted_bytes;
    uint64_t total_upper;
    int context_tokens, generation_tokens;
} HeptaPromptBudget;

static HeptaPromptBudget hepta_prompt_budget;

static bool hepta_check_prompt_budget(size_t formatted_bytes, int generation, int context) {
    hepta_prompt_budget = (HeptaPromptBudget){.checked=true, .formatted_bytes=formatted_bytes,
        .context_tokens=context, .generation_tokens=generation};
    if (formatted_bytes == 0 || generation < 1 || generation > 1024 ||
            (context != 4096 && context != 8192)) return false;
    uint64_t overhead = HEPTA_BOS_EOS_UPPER + HEPTA_RESERVED_TOKENS + (uint64_t)generation;
    if ((uint64_t)formatted_bytes > UINT64_MAX - overhead) return false;
    hepta_prompt_budget.total_upper = (uint64_t)formatted_bytes + overhead;
    hepta_prompt_budget.admitted = hepta_prompt_budget.total_upper <= (uint64_t)context;
    return hepta_prompt_budget.admitted;
}

static void hepta_write_prompt_budget(FILE *file) {
    fprintf(file, "\"prompt_budget\":{\"method\":\"lfm3_rendered_utf8_bytes_upper_bound\","
        "\"is_exact_token_count\":false,\"model_contract_sha256\":\"%s\","
        "\"checked\":%s,\"admitted\":%s,\"formatted_utf8_bytes\":%zu,"
        "\"bos_eos_upper\":%u,\"generation_tokens\":%d,\"reserved_tokens\":%u,"
        "\"total_context_upper\":%" PRIu64 ",\"context_tokens\":%d},",
        HEPTA_MODEL_SHA256, hepta_prompt_budget.checked?"true":"false",
        hepta_prompt_budget.admitted?"true":"false", hepta_prompt_budget.formatted_bytes,
        HEPTA_BOS_EOS_UPPER, hepta_prompt_budget.generation_tokens, HEPTA_RESERVED_TOKENS,
        hepta_prompt_budget.total_upper, hepta_prompt_budget.context_tokens);
}
#endif
