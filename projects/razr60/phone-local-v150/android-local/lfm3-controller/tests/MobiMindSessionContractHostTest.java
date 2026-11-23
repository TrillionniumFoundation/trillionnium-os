import org.trillionnium.hepta.local.MobiMindSessionContract;
import java.util.LinkedHashMap;
import java.util.Map;

public final class MobiMindSessionContractHostTest {
    private static int assertions;
    private static Map<String,Object> map(Object... pairs){Map<String,Object> out=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;}
    private static Map<String,Object> clean(){return map("schema","hepta.mobimind.diagnostic-session.v1","app_uid",10481,
        "updated_wall_ms",1700000000000L,"pending",false,"running",false,"actions_executed",false,"external_model_used",false,
        "automatic_resume",false,"cleanup_known",true,"native_binding_valid",true,"request_id","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "nonce_sha256",repeat('b',64),"owner_sha256",repeat('c',64),"status","completed","process_started",true,
        "process_exit_observed",true,"exit_code",0);}
    private static String repeat(char c,int n){StringBuilder out=new StringBuilder();while(n-->0)out.append(c);return out.toString();}
    private static void check(boolean yes,String reason){assertions++;if(!yes)throw new AssertionError(reason);}
    public static void main(String[] args){
        check(MobiMindSessionContract.clean(clean(),10481),"known completed, observed owned exit permits a new nonce");
        for(String key:new String[]{"pending","running","actions_executed","external_model_used","automatic_resume"}){
            Map<String,Object> v=clean();v.put(key,true);check(!MobiMindSessionContract.clean(v,10481),"reject "+key);
        }
        for(Map.Entry<String,Object> e:map("schema","other","app_uid",10482,"updated_wall_ms",0,"cleanup_known",false,
            "native_binding_valid",false,"request_id","x","nonce_sha256","x","owner_sha256",null,"status","running",
            "process_started",false,"process_exit_observed",false,"exit_code",143).entrySet()){
            Map<String,Object> v=clean();v.put(e.getKey(),e.getValue());check(!MobiMindSessionContract.clean(v,10481),"reject completed field "+e.getKey());
        }
        for(String status:new String[]{"preflight_failed","cancelled_before_start","submission_failed"}){
            Map<String,Object> v=clean();v.putAll(map("status",status,"process_started",false,"process_exit_observed",false,"exit_code",null,"native_binding_valid",false));
            check(MobiMindSessionContract.clean(v,10481),"known no-start terminal "+status);
            v.put("process_started",true);v.put("process_exit_observed",true);v.put("exit_code",0);
            check(!MobiMindSessionContract.clean(v,10481),"no-start status cannot hide a spawned process");
        }
        for(String status:new String[]{"native_failed","cancelled","timed_out"}){
            Map<String,Object> v=clean();v.putAll(map("status",status,"exit_code",143,"native_binding_valid",false));
            check(MobiMindSessionContract.clean(v,10481),"known exited failure "+status);
            v.put("process_exit_observed",false);check(!MobiMindSessionContract.clean(v,10481),"unobserved failure cannot release");
        }
        Map<String,Object> v=clean();v.putAll(map("status","cancel_race","native_binding_valid",false));
        check(MobiMindSessionContract.clean(v,10481),"natural exit racing cancellation is clean but not a cancelled proof");
        v.put("status","cancelled");check(!MobiMindSessionContract.clean(v,10481),"exit zero cannot be called explicit cancellation");
        v=clean();v.putAll(map("status","cleanup_unknown","native_binding_valid",false));
        check(!MobiMindSessionContract.clean(v,10481),"unknown cleanup stays blocked even with stale success fields");
        v=clean();v.remove("native_binding_valid");check(!MobiMindSessionContract.clean(v,10481),"missing native-binding decision is not a clean record");
        for(Object bad:new Object[]{-1,256,0.0,"0",null}){v=clean();v.put("exit_code",bad);check(!MobiMindSessionContract.clean(v,10481),"invalid exit representation rejected");}
        check(!MobiMindSessionContract.clean(null,10481),"absent record must be handled by observed absence, not parser success");
        check(!MobiMindSessionContract.clean(clean(),2000),"shell UID is not ordinary App recovery proof");
        System.out.println("MobiMindSessionContractHostTest assertions="+assertions);
    }
}
