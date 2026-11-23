import org.trillionnium.hepta.local.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class UiVenusProcessContractHostTest {
    static int assertions;static UiVenusContract.Expected expected;static Map<String,Object> core;
    static void yes(boolean value){assertions++;if(!value)throw new AssertionError();}
    static Map<String,Object> good(){
        Map<String,Object> b=new LinkedHashMap<String,Object>();
        b.put("schema","hepta.ui-venus.app-process-binding.v1");b.put("worker_artifact_role","ordinary-app-model-only-candidate");b.put("request_id",expected.id);
        for(String k:new String[]{"expected_app_uid","uid","euid"})b.put(k,expected.uid);
        for(String k:new String[]{"expected_parent_pid","observed_parent_pid"})b.put(k,expected.parent);
        b.put("pid",12346);b.put("parent_package","org.trillionnium.hepta.local");b.put("parent_death_signal",9);
        for(String k:new String[]{"direct_parent_verified_before","direct_parent_verified_after","private_scope_verified_before","private_scope_verified_after","same_directory_bootstrap_verified"})b.put(k,true);
        b.put("core_return_code",0);b.put("wrapper_return_code",0);b.put("app_files_directory",expected.files);b.put("run_directory",expected.run);
        b.put("model_directory",expected.files+"/"+UiVenusPins.MODEL_DIRECTORY);b.put("native_result_path",expected.run+"/native-result.json");b.put("raw_output_path",expected.run+"/raw.txt");
        b.put("parent_cmdline_policy","exact-package-followed-only-by-NUL-padding");
        for(String when:new String[]{"before","after"}){
            byte[] padded=new byte[64];byte[] name="org.trillionnium.hepta.local".getBytes(StandardCharsets.UTF_8);System.arraycopy(name,0,padded,0,name.length);
            b.put("parent_cmdline_bytes_"+when,padded.length);b.put("parent_cmdline_sha256_"+when,MobiMindContract.sha(padded));
            b.put("parent_status_sha256_"+when,MobiMindContract.sha(when.getBytes(StandardCharsets.UTF_8)));
        }
        for(String k:new String[]{"selinux_domain_proven","ordinary_app_qualification_claimed","native_action_authorized","actions_dispatched"})b.put(k,false);
        return b;
    }
    public static void main(String[] args)throws Exception{
        Path p=Paths.get("tests/ui-venus");UiVenusInputContract.Inputs inputs=UiVenusInputContract.verify(Files.readAllBytes(p.resolve("FIXTURE.json")),Files.readAllBytes(p.resolve("owner.txt")),Files.readAllBytes(p.resolve("prompt.txt")),Files.readAllBytes(p.resolve("system.txt")),Files.readAllBytes(p.resolve("screen.png")),Files.readAllBytes(Paths.get("provenance/ui-venus-app-r1/official-system-template.txt")));
        expected=new UiVenusContract.Expected("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",10481,12345,"/data/user/0/org.trillionnium.hepta.local/files","/data/app/test/lib/arm64",inputs);
        core=new LinkedHashMap<String,Object>();core.put("pid",12346);
        yes(UiVenusProcessContract.verify(good(),core,expected,0).isEmpty());
        Map<String,Object> negatives=new LinkedHashMap<String,Object>();
        negatives.put("schema","hepta.ui-venus.app-process-binding.v2");negatives.put("uid",2000);negatives.put("expected_app_uid",2000);
        negatives.put("expected_parent_pid",12347);negatives.put("observed_parent_pid",12347);negatives.put("pid",12345);negatives.put("parent_package","org.trillionnium.hepta.local:child");
        negatives.put("parent_death_signal",0);negatives.put("direct_parent_verified_after",false);negatives.put("private_scope_verified_after",false);
        negatives.put("same_directory_bootstrap_verified",false);negatives.put("wrapper_return_code",78);negatives.put("core_return_code",124);
        negatives.put("app_files_directory","/data/local/tmp");negatives.put("raw_output_path",expected.run+"/other.txt");
        negatives.put("parent_cmdline_sha256_before",MobiMindContract.sha("sh".getBytes(StandardCharsets.UTF_8)));negatives.put("parent_cmdline_bytes_after",4097);
        negatives.put("parent_status_sha256_after",null);negatives.put("actions_dispatched",true);negatives.put("selinux_domain_proven",true);
        for(Map.Entry<String,Object> n:negatives.entrySet()){Map<String,Object> b=good();b.put(n.getKey(),n.getValue());yes(!UiVenusProcessContract.verify(b,core,expected,0).isEmpty());}
        yes(!UiVenusProcessContract.verify(good(),core,expected,143).isEmpty());
        System.out.println("UI-Venus App process-binding contracts passed: "+assertions+"; no actual Android identity claimed");
    }
}
