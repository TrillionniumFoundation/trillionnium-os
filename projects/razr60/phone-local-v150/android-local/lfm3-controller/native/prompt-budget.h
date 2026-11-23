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
    bool checked, admitted, exact, input_ids_passed;
    size_t formatted_bytes;
    uint64_t total_upper;
    int context_tokens, generation_tokens;
    int32_t prompt_tokens;
    const char *model_sha256;
    char input_ids_sha256[65];
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

/* The caller must pass these exact counted IDs into geniex_llm_generate.
 * No byte-level proof, tokenizer estimate, or extra BOS/EOS is used here. */
static bool hepta_check_exact_prompt_budget(size_t formatted_bytes,int32_t tokens,int generation,int context,const char *model_sha256){
    hepta_prompt_budget=(HeptaPromptBudget){.checked=true,.exact=true,.formatted_bytes=formatted_bytes,
        .context_tokens=context,.generation_tokens=generation,.prompt_tokens=tokens,.model_sha256=model_sha256};
    if(!formatted_bytes||tokens<=0||generation<1||generation>1024||(context!=4096&&context!=8192)||!model_sha256)return false;
    hepta_prompt_budget.total_upper=(uint64_t)tokens+(uint64_t)generation+HEPTA_RESERVED_TOKENS;
    hepta_prompt_budget.admitted=hepta_prompt_budget.total_upper<=(uint64_t)context;
    return hepta_prompt_budget.admitted;
}

static void hepta_write_prompt_budget(FILE *file) {
    if(hepta_prompt_budget.exact){
        fprintf(file,"\"prompt_budget\":{\"method\":\"llama_tokenize_exact_same_input_ids\","
            "\"is_exact_token_count\":true,\"model_contract_sha256\":\"%s\","
            "\"tokenizer_source_commit\":\"19cce6919992fdffd92e0ac152caaf1e2b8f254e\","
            "\"checked\":%s,\"admitted\":%s,\"formatted_utf8_bytes\":%zu,"
            "\"add_special\":true,\"parse_special\":true,\"input_ids_passed_directly\":%s,"
            "\"prompt_tokens_exact\":%" PRId32 ",\"input_ids_count\":%" PRId32 ",\"input_ids_sha256\":\"%s\","
            "\"generation_tokens\":%d,\"reserved_tokens\":%u,\"total_context_tokens\":%" PRIu64 ",\"context_tokens\":%d},",
            hepta_prompt_budget.model_sha256?hepta_prompt_budget.model_sha256:"",
            hepta_prompt_budget.checked?"true":"false",hepta_prompt_budget.admitted?"true":"false",
            hepta_prompt_budget.formatted_bytes,hepta_prompt_budget.input_ids_passed?"true":"false",hepta_prompt_budget.prompt_tokens,hepta_prompt_budget.prompt_tokens,
            hepta_prompt_budget.input_ids_sha256,hepta_prompt_budget.generation_tokens,HEPTA_RESERVED_TOKENS,
            hepta_prompt_budget.total_upper,hepta_prompt_budget.context_tokens);
        return;
    }
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
