import java.util.HashMap;
import java.util.Map;
import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.NativeBudgetVerifier;

/** Configuration and receipt contracts only; no model file or inference is opened. */
public final class Qwen35ProfileHostTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> configuration(String compute,int context){
        Map<String,Object> r=new HashMap<String,Object>();
        r.put("schema","hepta.local-runtime.v2");r.put("model_profile","qwen3.5-4b-q4_0");
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
        ModelProfile p=ModelProfile.named("qwen3.5-4b-q4_0");
        check(p==ModelProfile.QWEN35_4B,"unique closed Java profile");
        check(p.bytes==2583221408L&&p.bytes>Integer.MAX_VALUE,"whole artifact is not truncated to signed int32");
        check("298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb".equals(p.sha256),"whole-file identity");
        check("Qwen3.5-4B-Q4_0.gguf".equals(p.fileName)&&"qwen35".equals(p.architecture),"fixed filename and Qwen architecture");
        check("unsloth/Qwen3.5-4B-GGUF".equals(p.repository)&&"e87f176479d0855a907a41277aca2f8ee7a09523".equals(p.revision),"fixed upstream revision");
        check(p.exactTokenizationRequired&&p.minimumAvailableBytes==(5L<<30)&&p.minimumAvailableBytes>p.bytes,"exact tokens and explicit qualification headroom");
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
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"LFM3 byte method cannot authorize Qwen");
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
        for(String unknown:new String[]{"qwen35","Qwen3.5-4B","qwen3.5-14b-q4_0","../Qwen3.5-4B-Q4_0.gguf"}){
            boolean denied=false;try{ModelProfile.named(unknown);}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"family, other size and paths do not select the model");
        }
        ModelProfile p9=ModelProfile.named("qwen3.5-9b-q4_0");
        check(p9==ModelProfile.QWEN35_9B&&p9!=p,"9B is a separate closed identity");
        check(p9.bytes==5379417312L&&p9.bytes>0xffffffffL,"9B size is not truncated to unsigned int32");
        check("17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24".equals(p9.sha256),"9B whole-file identity");
        check("Qwen3.5-9B-Q4_0.gguf".equals(p9.fileName)&&"qwen35".equals(p9.architecture),"9B filename and existing architecture");
        check("unsloth/Qwen3.5-9B-GGUF".equals(p9.repository)&&"3885219b6810b007914f3a7950a8d1b469d598a5".equals(p9.revision),"9B fixed upstream revision");
        check(p9.exactTokenizationRequired&&p9.minimumAvailableBytes==(8L<<30)&&p9.minimumAvailableBytes>p9.bytes,"9B exact input admission and headroom");
        for(String compute:new String[]{"npu","gpu"}){
            Map<String,Object> fields=configuration(compute,8192);fields.put("model_profile",p9.id);
            LocalRuntimeConfig config9=LocalRuntimeConfig.fromFields(fields);
            check(config9.profile==p9&&config9.matchesResolvedDevice("npu".equals(compute)?"HTP0":"GPUOpenCL",false,-1),"9B explicit requested device retained");
            check(NativeBudgetVerifier.valid(proof(p9,8192),config9,256,7680),"9B exact input proof accepted");
            check(!NativeBudgetVerifier.valid(proof(p,8192),config9,256,7680),"same-architecture 4B proof cannot authorize 9B");
            LocalRuntimeConfig config4=LocalRuntimeConfig.fromFields(configuration(compute,8192));
            check(!NativeBudgetVerifier.valid(proof(p9,8192),config4,256,7680),"same-architecture 9B proof cannot authorize 4B");
        }
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3&&LocalRuntimeConfig.defaults().contextTokens==8192,"default model and context unchanged");
        System.out.println("PASS "+checks+" Qwen3.5 4B/9B closed-profile/exact-receipt contracts; phone_tested=false; inference=false");
    }
}
