import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.NativeBudgetVerifier;
import java.util.HashMap;
import java.util.Map;

/** Synthetic receipts exercise admission policy, not model/tokenizer execution. */
public final class Lfm3ExactTokenHostTest {
    private static int assertions;
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static String repeat(char value,int count){char[] text=new char[count];java.util.Arrays.fill(text,value);return new String(text);}
    private static Map<String,Object> receipt(LocalRuntimeConfig config,int tokens){
        Map<String,Object> value=new HashMap<String,Object>();
        value.put("method","llama_tokenize_exact_same_input_ids");
        value.put("model_contract_sha256",ModelProfile.LFM3.sha256);
        value.put("tokenizer_source_commit",ModelProfile.LLAMA_COMMIT);
        value.put("formatted_utf8_bytes",18000);
        value.put("checked",true);value.put("admitted",true);value.put("is_exact_token_count",true);
        value.put("context_tokens",config.contextTokens);value.put("generation_tokens",256);value.put("reserved_tokens",256);
        value.put("add_special",true);value.put("parse_special",true);value.put("input_ids_passed_directly",true);
        value.put("prompt_tokens_exact",tokens);value.put("input_ids_count",tokens);value.put("total_context_tokens",tokens+512);
        value.put("input_ids_sha256",repeat('a',64));return value;
    }
    public static void main(String[] args){
        ModelProfile model=ModelProfile.LFM3;
        check(model.exactTokenizationRequired&&"lfm3".equals(model.architecture),"LFM3 exact profile selected");
        check(model.bytes==1049615680L&&model.minimumAvailableBytes==(3L<<30)
                &&"43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452".equals(model.sha256),"artifact and memory gates unchanged");
        check(LocalRuntimeConfig.defaults().profile==model&&LocalRuntimeConfig.defaults().contextTokens==8192,"default profile and context unchanged");
        check(ConservativeTokenBudget.GENERATION==256&&ConservativeTokenBudget.RESERVED==256,"output and reserve unchanged");
        for(int context:new int[]{4096,8192})for(String compute:new String[]{"npu","gpu"}){
            LocalRuntimeConfig config=new LocalRuntimeConfig(model,compute,context,4);
            ConservativeTokenBudget projection=ConservativeTokenBudget.estimate("system",repeat('中',6000),config);
            check(!projection.admitted&&!projection.provenUpperBound&&projection.mayAttemptNative(),"oversize Java projection permits only native admission attempt");
            check(!ConservativeTokenBudget.METHOD.equals(projection.method),"legacy byte method is not an exact count");
            int count=context-512;
            Map<String,Object> valid=receipt(config,count);
            check(NativeBudgetVerifier.valid(valid,config,256,count),"native token boundary accepted despite larger UTF-8 byte count");
            check(!NativeBudgetVerifier.valid(receipt(config,count+1),config,256,count+1),"one actual token overflow rejected");
            check(!NativeBudgetVerifier.valid(valid,config,256,count-1),"SDK consumed token count mismatch rejected");
            for(String key:new String[]{"method","model_contract_sha256","tokenizer_source_commit","formatted_utf8_bytes",
                    "checked","admitted","is_exact_token_count","context_tokens","generation_tokens","reserved_tokens",
                    "add_special","parse_special","input_ids_passed_directly","prompt_tokens_exact","input_ids_count",
                    "total_context_tokens","input_ids_sha256"}){
                Map<String,Object> bad=new HashMap<String,Object>(valid);bad.remove(key);
                check(!NativeBudgetVerifier.valid(bad,config,256,count),"missing exact proof rejected: "+key);
            }
            for(Object tokens:new Object[]{Integer.valueOf(0),Integer.valueOf(-1),Long.valueOf(Long.MAX_VALUE),"7680",Double.valueOf(count)}){
                Map<String,Object> bad=new HashMap<String,Object>(valid);bad.put("prompt_tokens_exact",tokens);
                check(!NativeBudgetVerifier.valid(bad,config,256,count),"invalid or mismatched exact token count rejected");
            }
            Map<String,Object> bad=new HashMap<String,Object>(valid);bad.put("input_ids_passed_directly",false);
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"retokenized string path cannot authorize exact profile");
            bad=new HashMap<String,Object>(valid);bad.put("model_contract_sha256",ModelProfile.GEMMA4_E4B.sha256);
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"another pinned model cannot authorize LFM3");
            bad=new HashMap<String,Object>(valid);bad.put("input_ids_sha256",repeat('A',64));
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"malformed ID digest rejected");
            bad=new HashMap<String,Object>(valid);bad.put("admitted",false);
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"native refusal remains refusal");
            bad=new HashMap<String,Object>(valid);bad.put("formatted_utf8_bytes",262145);
            check(!NativeBudgetVerifier.valid(bad,config,256,count),"formatted input size gate remains active");
            Map<String,Object> legacy=new HashMap<String,Object>(valid);
            legacy.put("method","lfm3_rendered_utf8_bytes_upper_bound");legacy.put("is_exact_token_count",false);
            legacy.put("formatted_utf8_bytes",100);legacy.put("bos_eos_upper",2);legacy.put("total_context_upper",614);
            check(!NativeBudgetVerifier.valid(legacy,config,256,count),"old byte-bound receipt cannot authorize LFM3 even when it fits");
        }
        System.out.println("PASS "+assertions+" LFM3 exact-token contracts; model_or_tokenizer_executed=false; phone_tested=false");
    }
}
