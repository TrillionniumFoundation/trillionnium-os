import java.util.HashMap;
import java.util.Map;
import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.NativeBudgetVerifier;

/** Configuration and receipt contracts only; no model file or inference is opened. */
public final class Lfm25MoeProfileHostTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> configuration(String compute,int context){
        Map<String,Object> r=new HashMap<String,Object>();
        r.put("schema","hepta.local-runtime.v2");r.put("model_profile","lfm2.5-8b-a1b-q4_0");
        r.put("compute",compute);r.put("context_tokens",context);r.put("threads",4);return r;
    }
    private static Map<String,Object> proof(ModelProfile p,int context){
        int tokens=context-ConservativeTokenBudget.GENERATION-ConservativeTokenBudget.RESERVED;
        Map<String,Object> r=new HashMap<String,Object>();
        r.put("method","llama_tokenize_exact_same_input_ids");r.put("model_contract_sha256",p.sha256);
        r.put("tokenizer_source_commit",ModelProfile.LLAMA_COMMIT);r.put("formatted_utf8_bytes",16000);
        r.put("checked",true);r.put("admitted",true);r.put("is_exact_token_count",true);
        r.put("context_tokens",context);r.put("generation_tokens",256);r.put("reserved_tokens",256);
        r.put("add_special",true);r.put("parse_special",true);r.put("input_ids_passed_directly",true);
        r.put("prompt_tokens_exact",tokens);r.put("input_ids_count",tokens);r.put("total_context_tokens",context);
        r.put("input_ids_sha256","0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");return r;
    }
    public static void main(String[] ignored){
        ModelProfile p=ModelProfile.named("lfm2.5-8b-a1b-q4_0");
        check(p==ModelProfile.LFM25_8B_A1B,"unique closed Java profile");
        check(p.bytes==4844678368L&&p.bytes>0xffffffffL,"whole artifact is not truncated to uint32");
        check("48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715".equals(p.sha256),"whole-file identity");
        check("LFM2.5-8B-A1B-Q4_0.gguf".equals(p.fileName)&&"lfm2moe".equals(p.architecture),"fixed filename and MoE architecture");
        check("LiquidAI/LFM2.5-8B-A1B-GGUF".equals(p.repository)&&"49c14831707011e64d70b2ebd8462ba08d608434".equals(p.revision),"fixed upstream revision");
        check(p.exactTokenizationRequired&&p.minimumAvailableBytes==(7L<<30)&&p.minimumAvailableBytes>p.bytes,"exact tokens and explicit qualification headroom");
        for(String compute:new String[]{"npu","gpu"})for(int context:new int[]{4096,8192}){
            LocalRuntimeConfig config=LocalRuntimeConfig.fromFields(configuration(compute,context));
            check(config.profile==p,"explicit model choice retained");
            check(config.matchesResolvedDevice("npu".equals(compute)?"HTP0":"GPUOpenCL",false,-1),"exact requested accelerator");
            check(!config.matchesResolvedDevice("CPU",false,-1)&&!config.matchesResolvedDevice(config.expectedDevice(),true,-1)
                    &&!config.matchesResolvedDevice(config.expectedDevice(),false,0),"CPU/coercion/no-offload receipt rejected");
            ConservativeTokenBudget projection=ConservativeTokenBudget.estimate("system","中文😀",config);
            check(!projection.provenUpperBound&&!ConservativeTokenBudget.METHOD.equals(projection.method),"does not inherit LFM3 byte proof");
            int count=context-512;Map<String,Object> valid=proof(p,context);
            check(NativeBudgetVerifier.valid(valid,config,256,count),"same-input-ID exact boundary accepted");
            check(!NativeBudgetVerifier.valid(valid,config,256,count-1),"SDK consumed token disagreement rejected");
            for(String field:new String[]{"input_ids_sha256","input_ids_passed_directly","tokenizer_source_commit","model_contract_sha256","is_exact_token_count"}){
                Map<String,Object> bad=new HashMap<String,Object>(valid);bad.remove(field);
                check(!NativeBudgetVerifier.valid(bad,config,256,count),"missing exact proof rejected");
            }
            Map<String,Object> bad=new HashMap<String,Object>(valid);bad.put("model_contract_sha256",ModelProfile.GEMMA4_E4B.sha256);
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"another allowed model cannot authorize this profile");
            bad=new HashMap<String,Object>(valid);bad.put("method","lfm3_rendered_utf8_bytes_upper_bound");bad.put("is_exact_token_count",false);
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"LFM3 byte method cannot authorize MoE");
            bad=new HashMap<String,Object>(valid);bad.put("prompt_tokens_exact",count+1);bad.put("input_ids_count",count+1);bad.put("total_context_tokens",context+1);
            check(!NativeBudgetVerifier.valid(bad,config,256,count+1),"one-token overflow rejected");
        }
        for(int context:new int[]{128000,16384,2048}){
            boolean rejected=false;try{LocalRuntimeConfig.fromFields(configuration("npu",context));}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"model maximum does not widen app context allowlist");
        }
        Map<String,Object> bad=configuration("cpu",8192);boolean rejected=false;
        try{LocalRuntimeConfig.fromFields(bad);}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"no automatic CPU mode added");
        bad=configuration("npu",8192);bad.put("model_sha256",p.sha256);rejected=false;
        try{LocalRuntimeConfig.fromFields(bad);}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"caller cannot override closed artifact identity");
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3&&LocalRuntimeConfig.defaults().contextTokens==8192,"default model and context unchanged");
        System.out.println("PASS "+checks+" LFM2.5 MoE closed-profile/exact-receipt contracts; phone_tested=false; inference=false");
    }
}
