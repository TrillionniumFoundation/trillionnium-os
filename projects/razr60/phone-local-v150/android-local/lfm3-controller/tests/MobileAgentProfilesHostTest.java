import java.util.HashMap;
import java.util.Map;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelProfile;
public final class MobileAgentProfilesHostTest {
    private static int checks;
    private static void check(boolean v,String m){checks++;if(!v)throw new AssertionError(m);}
    public static void main(String[] args){
        ModelProfile[] candidates={ModelProfile.BONSAI2_9B,ModelProfile.ORVENA4B};
        String[] ids={"bonsai2-9b-q2_0","orvena-4b-q4_k_m"};
        long[] sizes={2556640128L,2783447904L},memory={6L<<30,5L<<30};
        for(int i=0;i<candidates.length;i++){
            ModelProfile p=candidates[i];
            check(ModelProfile.named(ids[i])==p,"unique closed profile");
            check(p.bytes==sizes[i]&&p.bytes>Integer.MAX_VALUE,"whole artifact size");
            check(p.exactTokenizationRequired&&"qwen35".equals(p.architecture),"exact architecture proof");
            check(p.minimumAvailableBytes==memory[i]&&p.minimumAvailableBytes>p.bytes,"admission headroom");
            Map<String,Object> f=new HashMap<String,Object>();
            f.put("schema","hepta.local-runtime.v2");f.put("model_profile",ids[i]);f.put("compute","npu");f.put("context_tokens",4096);f.put("threads",4);
            LocalRuntimeConfig c=LocalRuntimeConfig.fromFields(f);
            check(c.profile==p&&c.matchesResolvedDevice("HTP0",false,-1),"explicit NPU identity");
            check(!c.matchesResolvedDevice("CPU",false,-1)&&!c.matchesResolvedDevice("HTP0",true,-1)&&!c.matchesResolvedDevice("HTP0",false,0),"fallback rejected");
            f.put("model_sha256",p.sha256);boolean denied=false;
            try{LocalRuntimeConfig.fromFields(f);}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"caller cannot override artifact");
        }
        check(!candidates[0].sha256.equals(candidates[1].sha256),"distinct identity despite common architecture");
        for(String name:new String[]{"bonsai2","orvena","../Ternary-Bonsai-2-9B-Q2_0.gguf"}){
            boolean denied=false;try{ModelProfile.named(name);}catch(IllegalArgumentException expected){denied=true;}
            check(denied,"no family or path aliases");
        }
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3,"default unchanged");
        System.out.println("PASS "+checks+" mobile profile checks; phone_tested=false; inference=false");
    }
}
