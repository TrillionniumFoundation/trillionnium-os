import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.NativeBudgetVerifier;
import java.util.HashMap;
import java.util.Map;

/** Real configuration/budget classes, including the E4B >4 GiB boundary. */
public final class Gemma4ProfileHostTest {
    private static int count;
    private static void check(boolean value,String message){count++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> config(ModelProfile profile,String compute,int context){
        Map<String,Object> value=new HashMap<>();value.put("schema","hepta.local-runtime.v2");
        value.put("model_profile",profile.id);value.put("compute",compute);value.put("context_tokens",context);value.put("threads",4);return value;
    }
    private static Map<String,Object> budget(ModelProfile profile){
        Map<String,Object> value=new HashMap<>();value.put("method","llama_tokenize_exact_same_input_ids");
        value.put("model_contract_sha256",profile.sha256);value.put("tokenizer_source_commit",ModelProfile.LLAMA_COMMIT);
        value.put("formatted_utf8_bytes",12000);value.put("checked",true);value.put("admitted",true);value.put("is_exact_token_count",true);
        value.put("context_tokens",4096);value.put("generation_tokens",256);value.put("reserved_tokens",256);
        value.put("add_special",true);value.put("parse_special",true);value.put("input_ids_passed_directly",true);
        value.put("prompt_tokens_exact",3584);value.put("input_ids_count",3584);value.put("total_context_tokens",4096);
        value.put("input_ids_sha256","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");return value;
    }
    public static void main(String[] args){
        check(ModelProfile.GEMMA4_E4B.bytes==5154941280L&&ModelProfile.GEMMA4_E4B.bytes>0xffffffffL,"E4B exact size is not 32-bit truncated");
        check(ModelProfile.GEMMA4_E2B.bytes==3349516256L,"E2B exact artifact size");
        for(ModelProfile profile:new ModelProfile[]{ModelProfile.GEMMA4_E4B,ModelProfile.GEMMA4_E2B}){
            check(ModelProfile.named(profile.id)==profile&&"gemma4".equals(profile.architecture),"closed Gemma4 architecture profile");
            check(profile.revision.matches("[a-f0-9]{40}")&&profile.sha256.matches("[a-f0-9]{64}"),"fixed revision and whole-file identity");
            check(profile.exactTokenizationRequired&&profile.minimumAvailableBytes>profile.bytes,"exact tokenization and conservative headroom threshold");
            for(String compute:new String[]{"npu","gpu"})for(int context:new int[]{4096,8192}){
                LocalRuntimeConfig chosen=LocalRuntimeConfig.fromFields(config(profile,compute,context));
                check(chosen.profile==profile,"explicit profile survives config parsing");
                check(chosen.matchesResolvedDevice("npu".equals(compute)?"HTP0":"GPUOpenCL",false,-1),"exact accelerator selection");
                check(!chosen.matchesResolvedDevice("CPU",false,-1),"CPU selection rejected");
                ConservativeTokenBudget projection=ConservativeTokenBudget.estimate("system","中文😀",chosen);
                check(!projection.provenUpperBound&&projection.profile==profile,"Gemma does not inherit LFM byte proof");
            }
            LocalRuntimeConfig chosen=LocalRuntimeConfig.fromFields(config(profile,"npu",4096));
            Map<String,Object> proof=budget(profile);
            check(NativeBudgetVerifier.valid(proof,chosen,256,3584),"same exact IDs fit context");
            proof.put("model_contract_sha256",profile==ModelProfile.GEMMA4_E4B?ModelProfile.GEMMA4_E2B.sha256:ModelProfile.GEMMA4_E4B.sha256);
            check(!NativeBudgetVerifier.valid(proof,chosen,256,3584),"cross-size Gemma proof rejected");
            proof=budget(profile);proof.put("input_ids_passed_directly",false);
            check(!NativeBudgetVerifier.valid(proof,chosen,256,3584),"retokenization ambiguity rejected");
        }
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3,"existing default unchanged");
        System.out.println("PASS "+count+" Gemma4 profile/64-bit-size/exact-budget contracts; phone_tested=false");
    }
}
