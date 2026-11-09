import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionPolicy;
import org.trillionnium.hepta.local.LocalRuntimeConfig;
import org.trillionnium.hepta.local.ModelFileVerifier;
import org.trillionnium.hepta.local.ModelProfile;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class LocalPolicyHostTest {
    private static int checks;
    private static final String OBS="0123456789abcdef0123456789abcdef";
    private static final Set<String> APPS=new HashSet<>(Arrays.asList("com.android.settings","com.example.calc"));
    private static final Set<String> NODES=new HashSet<>(Arrays.asList("n1","n7"));
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void policy(String action,String pkg,String extras,String current,boolean accepted)throws Exception{
        if(("click".equals(action)||"type".equals(action)||"scroll".equals(action))&&extras.contains("\"node_id\""))extras=",\"node_label\":\"\""+extras;
        ActionDecision value=ActionDecision.parse("{\"action\":\""+action+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+pkg+"\""+extras+"}");
        java.util.Map<String,String> labels=new java.util.HashMap<String,String>();for(String node:NODES)labels.put(node,"");
        ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,current,labels);
        boolean allowed=true;try{ActionPolicy.validateTextDecision(value,current,APPS,targets);}catch(ActionDecision.InvalidActionException rejected){allowed=false;}
        check(allowed==accepted,action+" package="+pkg+" current="+current);
    }
    public static void main(String[] args)throws Exception{
        policy("back","android","","android",true);
        policy("done","android",",\"status\":\"success\",\"summary\":\"目标可见\"","android",true);
        policy("open","android","","com.android.settings",false);
        policy("open","com.android.settings","","android",true);
        policy("open","com.android.settings","","com.android.settings",false);
        policy("open","com.example.unseen","","android",false);
        policy("back","com.example.calc","","android",false);
        policy("click","android",",\"node_id\":\"n7\"","android",true);
        policy("click","android",",\"node_id\":\"n8\"","android",false);
        policy("click","android",",\"x\":20,\"y\":50","android",false);
        policy("find_app","android",",\"query\":\"com.example.unseen\",\"offset\":0","android",true);
        policy("find_app","com.example.calc",",\"query\":\"calc\",\"offset\":0","android",false);
        check(ActionPolicy.isReadOnlyDiscovery(ActionDecision.parse("{\"action\":\"find_app\",\"observation_id\":\""+OBS+"\",\"package\":\"android\",\"query\":\"\",\"offset\":0}")),"discovery is explicitly read-only");
        LocalRuntimeConfig defaults=LocalRuntimeConfig.defaults();
        check("npu".equals(defaults.compute)&&defaults.contextTokens==8192,"default NPU 8K");
        java.util.Map<String,Object> saved=new java.util.LinkedHashMap<String,Object>();
        saved.put("schema","hepta.local-runtime.v1");saved.put("compute","npu");saved.put("context_tokens",4096);saved.put("threads",4);
        LocalRuntimeConfig explicitLegacy=LocalRuntimeConfig.fromFields(saved);
        check(explicitLegacy.profile==ModelProfile.LFM3&&explicitLegacy.contextTokens==4096,"explicit legacy LFM3 4K is not migrated");
        saved.put("schema","hepta.local-runtime.v2");saved.put("model_profile",ModelProfile.GEMMA4_E4B.id);
        LocalRuntimeConfig explicitSelected=LocalRuntimeConfig.fromFields(saved);
        check(explicitSelected.profile==ModelProfile.GEMMA4_E4B&&explicitSelected.contextTokens==4096,"explicit selected profile/context are preserved");
        check(defaults.matchesResolvedDevice("HTP0",false,-1),"NPU exact identity");
        check(!defaults.matchesResolvedDevice("CPU",false,-1),"CPU coercion rejected");
        check(!defaults.matchesResolvedDevice("HTP0",true,-1),"device warning rejected");
        check(!defaults.matchesResolvedDevice("HTP0",false,0),"zero offload rejected");
        LocalRuntimeConfig gpu=new LocalRuntimeConfig("gpu",8192,8);
        check(gpu.matchesResolvedDevice("GPUOpenCL",false,-1),"explicit GPU 8K");
        check(!gpu.matchesResolvedDevice("HTP0",false,-1),"wrong accelerator rejected");
        for(String compute:new String[]{"auto","cpu","hybrid","NPU","http://localhost","npu;sh"}){
            boolean rejected=false;try{new LocalRuntimeConfig(compute,4096,4);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"invalid compute rejected");
        }
        for(int ctx:new int[]{0,2048,4097,32768}){
            boolean rejected=false;try{new LocalRuntimeConfig("npu",ctx,4);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"unreviewed context rejected");
        }
        java.io.File fake=java.io.File.createTempFile("hepta-wrong-model-",".gguf");
        try{
            try(java.io.FileOutputStream stream=new java.io.FileOutputStream(fake)){stream.write("GGUF".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
            boolean rejected=false;try{new ModelFileVerifier().verify(fake,()->false);}catch(java.io.IOException expected){rejected=true;}
            check(rejected,"partial model cannot reach native process");
        }finally{fake.delete();}
        System.out.println("PASS "+checks+" local action/runtime/model contract assertions; phone_tested=false");
    }
}
