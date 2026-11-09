import org.trillionnium.hepta.local.ModelProfile;

/** Artifact registration only: does not establish model load, RAM or phone quality. */
public final class Qwen35ProfileHostTest {
    private static void require(boolean value,String message){if(!value)throw new AssertionError(message);}
    public static void main(String[] args){
        ModelProfile p=ModelProfile.named("qwen35-4b-q4_0");
        require(p==ModelProfile.QWEN35_4B,"exact public profile identity");
        require("unsloth/Qwen3.5-4B-GGUF".equals(p.repository),"conversion repository");
        require("1a02dbed1cdfe73efc3fa519c54126befb4faf68".equals(p.revision),"revision");
        require("Qwen3.5-4B-Q4_0.gguf".equals(p.fileName)&&p.bytes==2583221408L,"artifact and unsigned-size handling");
        require("298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb".equals(p.sha256),"full digest");
        require("qwen35".equals(p.architecture)&&p.exactTokenizationRequired,"family and exact token policy");
        require(p.minimumAvailableBytes==(6L<<30),"conservative admission policy, not measured peak");
        require(ModelProfile.named("lfm2.5-8b-a1b-q4_0")==ModelProfile.LFM25_8B_A1B,"Code22 LFM identity preserved");
        require(ModelProfile.LFM25_8B_A1B.minimumAvailableBytes==(7L<<30),"Code22 LFM policy preserved");
        for(String invalid:new String[]{"qwen35","Qwen3.5-4B","../Qwen3.5-4B-Q4_0.gguf","qwen35-4b-q4_0 ","lfm25-8b-a1b-q4_0",null}){
            boolean rejected=false;
            try{ModelProfile.named(invalid);}catch(IllegalArgumentException expected){rejected=true;}
            require(rejected,"unknown identity rejected: "+invalid);
        }
        System.out.println("PASS Qwen registration, Code22 LFM preservation and closed identity policy; inference=false");
    }
}
