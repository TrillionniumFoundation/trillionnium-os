import java.util.HashMap;
import java.util.Map;
import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.NativeBudgetVerifier;

/** Real Java configuration/receipt consumers; no weights, tokenizer or device. */
public final class Nanbeige42ProfileHostTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Map<String,Object> config(String compute,int context){
        Map<String,Object> value=new HashMap<String,Object>();
        value.put("schema","hepta.local-runtime.v2");value.put("model_profile","nanbeige4.2-3b-q4_k_m");
        value.put("compute",compute);value.put("context_tokens",context);value.put("threads",4);return value;
    }
    private static Map<String,Object> receipt(ModelProfile profile,int context,int count){
        Map<String,Object> value=new HashMap<String,Object>();
        value.put("method","llama_tokenize_exact_same_input_ids");value.put("model_contract_sha256",profile.sha256);
        value.put("tokenizer_source_commit",ModelProfile.LLAMA_COMMIT);value.put("formatted_utf8_bytes",18000);
        value.put("checked",true);value.put("admitted",true);value.put("is_exact_token_count",true);
        value.put("context_tokens",context);value.put("generation_tokens",256);value.put("reserved_tokens",256);
        value.put("add_special",true);value.put("parse_special",true);value.put("input_ids_passed_directly",true);
        value.put("prompt_tokens_exact",count);value.put("input_ids_count",count);value.put("total_context_tokens",count+512);
        value.put("input_ids_sha256","0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");return value;
    }
    private static void rejectConfig(Map<String,Object> value){
        boolean rejected=false;try{LocalRuntimeConfig.fromFields(value);}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"unsupported/overridden runtime configuration must remain rejected");
    }
    public static void main(String[] ignored){
        ModelProfile p=ModelProfile.named("nanbeige4.2-3b-q4_k_m");
        check(p==ModelProfile.NANBEIGE42_3B,"one closed profile");
        check(p.bytes==2684023968L&&p.bytes>Integer.MAX_VALUE,"artifact length is not signed-32-bit truncated");
        check("Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf".equals(p.fileName)&&"nanbeige".equals(p.architecture),"fixed file and architecture");
        check("b92d2e35c9876b0c4bc671996360204f4149d0546c23d5954d5eb3b106c81f24".equals(p.sha256),"whole-file SHA");
        check("bartowski/Nanbeige_Nanbeige4.2-3B-GGUF".equals(p.repository)
                &&"210b0d6d6c1046044c7ea9d16c9ce3b5716ec2d2".equals(p.revision),"fixed conversion source revision");
        check(p.exactTokenizationRequired&&p.minimumAvailableBytes==(6L<<30),"exact proof and experimental 6 GiB admission");
        StringBuilder large=new StringBuilder();for(int i=0;i<20000;i++)large.append('x');
        for(String compute:new String[]{"npu","gpu"})for(int context:new int[]{4096,8192}){
            LocalRuntimeConfig selected=LocalRuntimeConfig.fromFields(config(compute,context));
            check(selected.profile==p&&selected.contextTokens==context,"existing explicit context contract preserved");
            check(selected.matchesResolvedDevice("npu".equals(compute)?"HTP0":"GPUOpenCL",false,-1),"requested backend is exact");
            check(!selected.matchesResolvedDevice("CPU",false,-1)&&!selected.matchesResolvedDevice(selected.expectedDevice(),true,-1)
                    &&!selected.matchesResolvedDevice(selected.expectedDevice(),false,0),"CPU/coercion/no-offload rejected");
            ConservativeTokenBudget estimate=ConservativeTokenBudget.estimate("system",large.toString(),selected);
            check(!estimate.admitted&&!estimate.provenUpperBound&&estimate.mayAttemptNative(),"v30 estimate stays advisory for exact profile");
            int count=context-512;Map<String,Object> proof=receipt(p,context,count);
            check(NativeBudgetVerifier.valid(proof,selected,256,count),"exact boundary accepted");
            check(!NativeBudgetVerifier.valid(proof,selected,256,count-1),"SDK prompt count mismatch rejected");
            check(!NativeBudgetVerifier.valid(receipt(p,context,count+1),selected,256,count+1),"one real token beyond context rejected");
            for(String field:new String[]{"checked","admitted","is_exact_token_count","input_ids_passed_directly",
                    "input_ids_count","input_ids_sha256","tokenizer_source_commit","model_contract_sha256","reserved_tokens"}){
                Map<String,Object> bad=new HashMap<String,Object>(proof);bad.remove(field);
                check(!NativeBudgetVerifier.valid(bad,selected,256,count),"missing exact evidence rejected: "+field);
            }
            Map<String,Object> bad=new HashMap<String,Object>(proof);bad.put("model_contract_sha256",ModelProfile.ORVENA4B.sha256);
            check(!NativeBudgetVerifier.valid(bad,selected,256,count),"another allowed model cannot authorize this one");
            bad=new HashMap<String,Object>(proof);bad.put("method","lfm3_rendered_utf8_bytes_upper_bound");bad.put("is_exact_token_count",false);
            check(!NativeBudgetVerifier.valid(bad,selected,256,count),"LFM3 proof cannot authorize Nanbeige");
            bad=new HashMap<String,Object>(proof);bad.put("formatted_utf8_bytes",262145);
            check(!NativeBudgetVerifier.valid(bad,selected,256,count),"formatted input byte bound unchanged");
            bad=new HashMap<String,Object>(proof);bad.put("admitted",false);
            check(!NativeBudgetVerifier.valid(bad,selected,256,count),"native refusal cannot become success");
        }
        for(String name:new String[]{"nanbeige","Nanbeige4.2-3B","../Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf",null}){
            boolean rejected=false;try{ModelProfile.named(name);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"aliases and paths cannot select a model");
        }
        for(int context:new int[]{2048,16384,131072})rejectConfig(config("npu",context));
        rejectConfig(config("cpu",4096));
        Map<String,Object> bad=config("npu",4096);bad.put("model_path","/tmp/arbitrary.gguf");rejectConfig(bad);
        bad=config("npu",4096);bad.put("model_sha256",p.sha256);rejectConfig(bad);
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3&&LocalRuntimeConfig.defaults().contextTokens==8192,
                "default model and existing default context unchanged");
        check(new LocalRuntimeConfig(ModelProfile.ORVENA4B,"npu",8192,4).contextTokens==8192,"other explicit profiles unchanged");
        System.out.println("PASS "+checks+" Nanbeige profile/configuration/exact-proof checks; phone_tested=false; model_loaded=false");
    }
}
