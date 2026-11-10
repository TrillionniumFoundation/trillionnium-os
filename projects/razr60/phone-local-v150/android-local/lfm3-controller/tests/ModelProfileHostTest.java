import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.NativeBudgetVerifier;
import java.util.HashMap;
import java.util.Map;

public final class ModelProfileHostTest {
    private static int count;
    private static void check(boolean value,String message){count++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> config(){
        Map<String,Object> value=new HashMap<>();value.put("schema","hepta.local-runtime.v2");
        value.put("model_profile",ModelProfile.MINICPM5.id);value.put("compute","npu");value.put("context_tokens",4096);value.put("threads",4);return value;
    }
    private static Map<String,Object> budget(){
        Map<String,Object> value=new HashMap<>();value.put("method","llama_tokenize_exact_same_input_ids");
        value.put("model_contract_sha256",ModelProfile.MINICPM5.sha256);value.put("tokenizer_source_commit",ModelProfile.LLAMA_COMMIT);
        value.put("formatted_utf8_bytes",12000);value.put("checked",true);value.put("admitted",true);value.put("is_exact_token_count",true);
        value.put("context_tokens",4096);value.put("generation_tokens",256);value.put("reserved_tokens",256);
        value.put("add_special",true);value.put("parse_special",true);value.put("input_ids_passed_directly",true);
        value.put("prompt_tokens_exact",3584);value.put("input_ids_count",3584);value.put("total_context_tokens",4096);
        value.put("input_ids_sha256","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");return value;
    }
    public static void main(String[] args){
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3,"default remains LFM3");
        check(LocalRuntimeConfig.MODEL_SHA256.equals(ModelProfile.LFM3.sha256)&&LocalRuntimeConfig.MODEL_BYTES==ModelProfile.LFM3.bytes,"original LFM3 pin unchanged");
        LocalRuntimeConfig chosen=LocalRuntimeConfig.fromFields(config());
        check(chosen.profile==ModelProfile.MINICPM5&&chosen.matchesResolvedDevice("HTP0",false,-1),"explicit MiniCPM NPU profile");
        check(ModelProfile.named(ModelProfile.SPARK.id)==ModelProfile.SPARK,"Spark closed allowlist entry");
        check(ModelProfile.named(ModelProfile.BOLT_E4B.id)==ModelProfile.BOLT_E4B
                &&ModelProfile.BOLT_E4B.bytes==6180446208L&&ModelProfile.BOLT_E4B.bytes>0xffffffffL
                &&ModelProfile.BOLT_E4B.minimumAvailableBytes==(8L<<30)
                &&ModelProfile.BOLT_E4B.exactTokenizationRequired
                &&ModelProfile.BOLT_E4B.architecture.equals("gemma4"),"experimental Bolt artifact, 64-bit size and admission threshold");
        check(ModelProfile.GEMMA4_E4B.minimumAvailableBytes==(7L<<30)
                &&LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3,"Bolt does not alter E4B admission or default profile");
        Map<String,Object> old=config();old.put("schema","hepta.local-runtime.v1");old.remove("model_profile");
        check(LocalRuntimeConfig.fromFields(old).profile==ModelProfile.LFM3,"legacy config stays LFM3");
        for(String key:new String[]{"model_profile","compute","context_tokens","threads","schema"}){
            Map<String,Object> broken=config();broken.remove(key);boolean rejected=false;
            try{LocalRuntimeConfig.fromFields(broken);}catch(IllegalArgumentException expected){rejected=true;}check(rejected,"missing "+key);
        }
        for(Object id:new Object[]{"llama","../MiniCPM5-2B-Q4_K_M.gguf","MiniCPM5",Integer.valueOf(1),null}){
            Map<String,Object> broken=config();broken.put("model_profile",id);boolean rejected=false;
            try{LocalRuntimeConfig.fromFields(broken);}catch(IllegalArgumentException expected){rejected=true;}check(rejected,"unknown/invalid profile rejected");
        }
        Map<String,Object> extra=config();extra.put("model_sha256",ModelProfile.MINICPM5.sha256);boolean rejected=false;
        try{LocalRuntimeConfig.fromFields(extra);}catch(IllegalArgumentException expected){rejected=true;}check(rejected,"cannot override pin");
        ConservativeTokenBudget projected=ConservativeTokenBudget.estimate("system","中文😀",chosen);
        check(!projected.provenUpperBound&&projected.profile.exactTokenizationRequired&&!projected.method.equals(ConservativeTokenBudget.METHOD),"new model never inherits LFM3 byte proof");
        check(NativeBudgetVerifier.valid(budget(),chosen,256,3584),"exact context boundary accepted even when UTF8 bytes exceed context");
        for(String field:new String[]{"model_contract_sha256","tokenizer_source_commit","is_exact_token_count","checked","admitted","add_special","parse_special","input_ids_passed_directly","input_ids_sha256","total_context_tokens"}){
            Map<String,Object> broken=budget();broken.remove(field);check(!NativeBudgetVerifier.valid(broken,chosen,256,3584),"missing native proof field "+field);
        }
        for(Object tokens:new Object[]{Integer.valueOf(3585),Integer.valueOf(0),Integer.valueOf(-1),Long.valueOf(Long.MAX_VALUE),"3584"}){
            Map<String,Object> broken=budget();broken.put("prompt_tokens_exact",tokens);check(!NativeBudgetVerifier.valid(broken,chosen,256,3584),"token counter mismatch/type/overflow denied");
        }
        check(!NativeBudgetVerifier.valid(budget(),chosen,256,3583),"SDK consumed count must match exact IDs");
        check(!NativeBudgetVerifier.valid(budget(),LocalRuntimeConfig.defaults(),256,3584),"cross-profile native proof rejected");
        Map<String,Object> forged=budget();forged.put("method","lfm3_rendered_utf8_bytes_upper_bound");
        check(!NativeBudgetVerifier.valid(forged,chosen,256,3584),"LFM3 proof cannot authorize MiniCPM");
        System.out.println("PASS "+count+" profile/config/exact-budget contracts; phone_tested=false");
    }
}
