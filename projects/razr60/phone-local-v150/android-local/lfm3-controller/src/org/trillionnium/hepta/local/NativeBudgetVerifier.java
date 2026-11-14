package org.trillionnium.hepta.local;

import java.util.Map;

/** Pure receipt validator: exact profiles, including LFM3, require same-input-ID proof. */
public final class NativeBudgetVerifier {
    private NativeBudgetVerifier(){}
    private static long number(Map<String,?> value,String key){
        Object item=value.get(key);return item instanceof Integer||item instanceof Long?((Number)item).longValue():-1;
    }
    public static boolean valid(Map<String,?> budget,LocalRuntimeConfig config,int generation,long sdkPromptTokens){
        if(budget==null||config==null||generation<1||generation>1024)return false;
        long bytes=number(budget,"formatted_utf8_bytes");
        if(!config.profile.sha256.equals(budget.get("model_contract_sha256"))||bytes<=0||bytes>262144L
                ||!Boolean.TRUE.equals(budget.get("checked"))||!Boolean.TRUE.equals(budget.get("admitted"))
                ||number(budget,"context_tokens")!=config.contextTokens||number(budget,"generation_tokens")!=generation
                ||number(budget,"reserved_tokens")!=ConservativeTokenBudget.RESERVED)return false;
        if(!config.profile.exactTokenizationRequired){
            long total=bytes+ConservativeTokenBudget.BOS_EOS_BOUND+generation+ConservativeTokenBudget.RESERVED;
            return "lfm3_rendered_utf8_bytes_upper_bound".equals(budget.get("method"))
                    &&Boolean.FALSE.equals(budget.get("is_exact_token_count"))
                    &&number(budget,"bos_eos_upper")==ConservativeTokenBudget.BOS_EOS_BOUND
                    &&number(budget,"total_context_upper")==total&&total<=config.contextTokens;
        }
        long count=number(budget,"prompt_tokens_exact");
        Object hash=budget.get("input_ids_sha256");
        long total=count+generation+ConservativeTokenBudget.RESERVED;
        return "llama_tokenize_exact_same_input_ids".equals(budget.get("method"))
                &&Boolean.TRUE.equals(budget.get("is_exact_token_count"))
                &&ModelProfile.LLAMA_COMMIT.equals(budget.get("tokenizer_source_commit"))
                &&Boolean.TRUE.equals(budget.get("add_special"))&&Boolean.TRUE.equals(budget.get("parse_special"))
                &&Boolean.TRUE.equals(budget.get("input_ids_passed_directly"))
                &&count>0&&count<=config.contextTokens&&count==number(budget,"input_ids_count")&&count==sdkPromptTokens
                &&hash instanceof String&&((String)hash).matches("[0-9a-f]{64}")
                &&number(budget,"total_context_tokens")==total&&total<=config.contextTokens;
    }
}
