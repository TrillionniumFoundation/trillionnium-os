import org.trillionnium.hepta.local.ConservativeTokenBudget;
import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.NativeBudgetVerifier;
import org.trillionnium.hepta.local.ObservedScrollActions;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import org.trillionnium.hepta.local.PromptActionDomain;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Java admission is not token proof. Compiles against the prior public API. */
public final class ExactPromptAdmissionHostTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static String repeat(String value,int count){StringBuilder out=new StringBuilder();for(int i=0;i<count;i++)out.append(value);return out.toString();}
    private static LocalRuntimeConfig config(ModelProfile profile,int context){return new LocalRuntimeConfig(profile,"npu",context,4);}
    private static Map<String,Object> nativeProof(ModelProfile profile,int context,int tokens){
        Map<String,Object> value=new HashMap<>();
        value.put("method","llama_tokenize_exact_same_input_ids");value.put("model_contract_sha256",profile.sha256);
        value.put("tokenizer_source_commit",ModelProfile.LLAMA_COMMIT);value.put("formatted_utf8_bytes",24000);
        value.put("checked",true);value.put("admitted",true);value.put("is_exact_token_count",true);
        value.put("context_tokens",context);value.put("generation_tokens",256);value.put("reserved_tokens",256);
        value.put("add_special",true);value.put("parse_special",true);value.put("input_ids_passed_directly",true);
        value.put("prompt_tokens_exact",tokens);value.put("input_ids_count",tokens);value.put("total_context_tokens",tokens+512);
        value.put("input_ids_sha256",repeat("a",64));return value;
    }
    public static void main(String[] ignored)throws Exception{
        // This assertion fails on the original Q implementation without any new API.
        // The large complete prompt is only admitted to native checking, never to tools.
        String system=repeat("s",3593),prompt=repeat("p",3000);
        LocalRuntimeConfig gemma=config(ModelProfile.GEMMA4_E4B,4096);
        ConservativeTokenBudget candidate=ConservativeTokenBudget.estimate(system,prompt,gemma);
        check(candidate.totalContextUpper>4096&&!candidate.provenUpperBound,"unproven heuristic exceeds context");
        check(candidate.admitted,"exact profile must reach native admission despite heuristic rejection");

        ModelProfile[] exact={ModelProfile.MINICPM5,ModelProfile.SPARK,ModelProfile.GEMMA4_E4B,ModelProfile.GEMMA4_E2B,
            ModelProfile.BOLT_E4B,ModelProfile.LFM25_8B_A1B,ModelProfile.QWEN35_4B,ModelProfile.QWEN35_9B,ModelProfile.BONSAI2_9B,ModelProfile.ORVENA4B};
        for(ModelProfile profile:exact)for(int context:new int[]{4096,8192}){
            LocalRuntimeConfig selected=config(profile,context);
            ConservativeTokenBudget large=ConservativeTokenBudget.estimate("system",repeat("x",context*2),selected);
            check(profile.exactTokenizationRequired&&!large.provenUpperBound&&large.totalContextUpper>context&&large.admitted,
                "profile-specific exact guard is authoritative: "+profile.id+"/"+context);
            int boundary=context-512;
            check(NativeBudgetVerifier.valid(nativeProof(profile,context,boundary),selected,256,boundary),"native exact boundary accepted");
            check(!NativeBudgetVerifier.valid(nativeProof(profile,context,boundary+1),selected,256,boundary+1),"actual one-token overflow still rejected");
            Map<String,Object> missing=nativeProof(profile,context,boundary);missing.remove("input_ids_passed_directly");
            check(!NativeBudgetVerifier.valid(missing,selected,256,boundary),"Java admission cannot replace same-ID native proof");
            Map<String,Object> heuristic=nativeProof(profile,context,boundary);heuristic.put("method",large.method);heuristic.put("is_exact_token_count",false);
            check(!NativeBudgetVerifier.valid(heuristic,selected,256,boundary),"diagnostic heuristic cannot authorize native result");
        }

        check(ConservativeTokenBudget.estimate(repeat("s",65536),repeat("p",65536),gemma).admitted,"each message may reach the existing byte boundary");
        check(!ConservativeTokenBudget.estimate("system",repeat("p",65537),gemma).admitted,"prompt byte limit unchanged");
        check(!ConservativeTokenBudget.estimate(repeat("s",65537),"prompt",gemma).admitted,"system byte limit unchanged");
        String utf8Boundary=repeat("界",21845)+"x";
        check(ConservativeTokenBudget.bytesUpper(utf8Boundary)==65536&&ConservativeTokenBudget.estimate("sys",utf8Boundary,gemma).admitted,
            "standard UTF-8, not character count, defines the boundary");
        check(!ConservativeTokenBudget.estimate("sys",utf8Boundary+"x",gemma).admitted,"multibyte input cannot bypass the byte limit");
        for(String invalid:new String[]{"\ud800","\udc00","x\u0000y","\ud800x"}){
            boolean rejected=false;try{ConservativeTokenBudget.estimate("sys",invalid,gemma);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"invalid Unicode/NUL remains rejected");
        }
        for(int context:new int[]{4096,8192}){
            int limit=context-256-256-512-2;
            check(ConservativeTokenBudget.estimate("sys",repeat("a",limit-3),context).admitted,"original LFM3 bound still admits its boundary");
            check(!ConservativeTokenBudget.estimate("sys",repeat("a",limit-2),context).admitted,"original LFM3 overflow still refused");
        }

        // A complete large action domain can proceed without dropping its last target.
        String pkg="com.example.fixture",observation=repeat("b",32),owner="完整指令：检查所有目标 <task>，不要改写这段 OWNER。";
        Map<String,String> labels=new LinkedHashMap<>();Set<String> required=new LinkedHashSet<>();
        StringBuilder full=new StringBuilder("UNTRUSTED_DATA\n");
        for(int i=0;i<40;i++){
            String id="n"+i,label=ObservedTargetLabels.project("目标"+i+repeat("可见",15));
            if(PromptActionDomain.requiresRetention(pkg,pkg,true,false,true,false,ObservedScrollActions.UNKNOWN))required.add(id);
            labels.put(id,label);full.append(id).append(' ').append(label).append('\n');
        }
        full.append("OWNER\n").append(owner);String complete=full.toString();
        check(ConservativeTokenBudget.estimate(system,complete,gemma).admitted,"complete owner and all 40 action targets admitted to exact checking");
        check(complete.endsWith("OWNER\n"+owner)&&labels.size()==40&&required.size()==40,"owner and complete target domain retained");
        Set<String> shown=new LinkedHashSet<>(labels.keySet());PromptActionDomain.requireComplete(required,shown);
        DecisionGrammar grammar=DecisionGrammar.create(observation,pkg,Collections.<String>emptySet(),required,
            Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),
            ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,observation,pkg,labels));
        check(grammar.targets.labels.keySet().equals(required),"exact admission does not alter grammar target bindings");
        shown.remove("n39");boolean missingRejected=false;
        try{PromptActionDomain.requireComplete(required,shown);}catch(IllegalStateException expected){missingRejected=true;}
        check(missingRejected,"large-prompt admission cannot excuse a missing required target");
        System.out.println("PASS "+checks+" Java-admission/native-proof/byte-limit/complete-target checks; no tokenizer, SDK, Android or phone executed");
    }
}
