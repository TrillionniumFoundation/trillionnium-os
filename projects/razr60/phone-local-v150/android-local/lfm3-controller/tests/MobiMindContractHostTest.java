import org.trillionnium.hepta.local.MobiMindContract;
import org.trillionnium.hepta.local.MobiMindPins;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class MobiMindContractHostTest {
    private static int assertions;
    private static Map<String,Object> map(Object... items){Map<String,Object> value=new LinkedHashMap<String,Object>();for(int i=0;i<items.length;i+=2)value.put((String)items[i],items[i+1]);return value;}
    private static void check(boolean valid,String why){assertions++;if(!valid)throw new AssertionError(why);}
    private static final String ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SHA="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static final byte[] RAW="{\"reasoning\":\"fixture\",\"action\":\"wait\",\"parameters\":{}}".getBytes(StandardCharsets.UTF_8);
    private static final MobiMindContract.Expected X=new MobiMindContract.Expected(ID,10481,1234,SHA,SHA,"/data/app/example/lib/arm64/libMNN.so",256,1224,2992,1024,256);
    private static Map<String,Object> terminal(){return map("schema","hepta.mobimind.model_only.v1","request_id",ID,"outcome","completed","uid",10481,"pid",4321,"expected_parent_pid",1234,"expected_exit_code",0,"receipt_complete",true,"actions_executed",false,"external_model_used",false,"http_resources_compiled",false);}
    private static Map<String,Object> receipt(){Map<String,Object> r=terminal();r.putAll(map(
        "generation_complete",true,"model_repo",MobiMindPins.MODEL_REPO,"model_revision",MobiMindPins.MODEL_REVISION,
        "mnn_revision",MobiMindPins.MNN_REVISION,"loaded_mnn_path",X.mnnPath,"loaded_mnn_sha256",MobiMindPins.MNN_SHA,
        "pinned_files_verified",11,"initial_input_binding",true,"post_generation_file_binding",true,
        "prompt_expected_sha256",SHA,"prompt_actual_sha256",SHA,"image_expected_sha256",SHA,"image_actual_sha256",SHA,
        "sampling","greedy","context_limit",4096,"max_new_tokens",256,"input_ids_hook_calls",1,"input_tokens_exact",100,"input_ids_sha256",SHA,
        "original_width",1224,"original_height",2992,"resized_width",416,"resized_height",1024,
        "requested_text_backend","opencl","requested_vision_backend","opencl","opencl_preflight",true,"backend_probe_qualified",true,
        "gpu_execution_observed",true,"all_gpu_claim",false,"opencl_runtime_selections",2,"opencl_execution_calls",8,"execution_errors",0,
        "cpu_execution_calls",3,"other_execution_calls",0,"runtime_selections",map("load:3->3",2),
        "operation_backend_counts",map("vision:3:Conv",map("calls",8,"error_calls",0),"vision:0:Shape",map("calls",3,"error_calls",0)),
        "raw_valid_utf8",true,"raw_bytes",RAW.length,"raw_sha256",MobiMindContract.sha(RAW),"mnn_context",map("status",1,"output_token_count",32),
        "sha256_dispatch",dispatch(true)));return r;}
    private static Map<String,Object> tokens(){return map("count",100,"max_new_tokens",256,"context_limit",4096,"encoding","signed-token-id-as-uint32-little-endian","sha256",SHA);}
    private static Map<String,Object> hash(long bytes,boolean hardware){long blocks=(bytes+72)/64;return map("complete",true,"bytes_hashed",bytes,"selected_hardware",hardware,
        "hash_backend",hardware?"armv8-sha2":"portable","hardware_blocks",hardware?blocks:0,"portable_blocks",hardware?0:blocks);}
    private static Map<String,Object> dispatch(boolean hardware){long bytes=0,blocks=0;for(MobiMindPins.FilePin p:MobiMindPins.modelFiles()){bytes+=p.bytes;blocks+=(p.bytes+72)/64;}
        return map("schema","hepta.mobimind.sha256-dispatch.v1","compiled_armv8_sha2",true,"runtime_hwcap_sha2",hardware,
            "model_files_hashed",11,"model_bytes_hashed",bytes,"model_hardware_blocks",hardware?blocks:0,"model_portable_blocks",hardware?0:blocks,
            "hash_backend",hardware?"armv8-sha2":"portable","complete_model_files_only",true,"padding_included_in_block_counts",true,
            "full_file_hash_each_request",true,"digest_cache",false,"prompt",hash(X.promptBytes,hardware),"image",hash(X.imageBytes,hardware),"loaded_library",hash(MobiMindPins.MNN_BYTES,hardware));}
    private static Map<String,Object> models(){return models(true);}
    private static Map<String,Object> models(boolean hardware){Map<String,Object> out=map();for(MobiMindPins.FilePin pin:MobiMindPins.modelFiles())out.put(pin.name,map("bytes",pin.bytes,"sha256",pin.sha256,"hash_execution",hash(pin.bytes,hardware)));return out;}
    private static List<String> verify(Map<String,Object> r){return MobiMindContract.verify(r,terminal(),tokens(),models(),RAW,X,0);}
    public static void main(String[] args)throws Exception{
        check(verify(receipt()).isEmpty(),"complete native evidence qualifies while recorded CPU helper calls remain visible");
        for(Map.Entry<String,Object> change:map("schema","other","request_id","cccccccccccccccccccccccccccccccc","uid",2000,
            "expected_parent_pid",1235,"loaded_mnn_sha256",SHA,"loaded_mnn_path","/data/local/tmp/libMNN.so",
            "model_revision","main","generation_complete",false,"post_generation_file_binding",false,"initial_input_binding",false,
            "pinned_files_verified",10,"prompt_actual_sha256","0"+SHA.substring(1),"image_actual_sha256","0"+SHA.substring(1),
            "input_tokens_exact",4096,"input_ids_hook_calls",2,"requested_text_backend","cpu","requested_vision_backend","cpu",
            "opencl_runtime_selections",0,"opencl_execution_calls",0,"all_gpu_claim",true,"execution_errors",1,
            "raw_sha256",SHA,"raw_valid_utf8",false,"raw_bytes",RAW.length+1,"actions_executed",true,
            "external_model_used",true,"http_resources_compiled",true,"outcome","max_tokens_reached").entrySet()){
            Map<String,Object> r=receipt();r.put(change.getKey(),change.getValue());check(!verify(r).isEmpty(),"reject "+change.getKey());
        }
        Map<String,Object> r=receipt();r.put("runtime_selections",map("load:3->3",2,"vision:3->0",1));check(!verify(r).isEmpty(),"runtime fallback cannot be hidden by positive GPU count");
        for(Map.Entry<String,Object> change:map("schema","other","model_files_hashed",10,"model_bytes_hashed",0,"model_hardware_blocks",0,
            "model_portable_blocks",1,"hash_backend","portable","full_file_hash_each_request",false,"digest_cache",true,"runtime_hwcap_sha2","true").entrySet()){
            r=receipt();Map<String,Object> dispatch=dispatch(true);dispatch.put(change.getKey(),change.getValue());r.put("sha256_dispatch",dispatch);
            check(!verify(r).isEmpty(),"reject hash dispatch "+change.getKey());
        }
        r=receipt();r.put("sha256_dispatch",dispatch(false));check(MobiMindContract.verify(r,terminal(),tokens(),models(false),RAW,X,0).isEmpty(),"honest complete portable SHA remains valid, without acceleration claim");
        Map<String,Object> broken=models();MobiMindContract.object(broken.get("llm.mnn.weight")).put("hash_execution",hash(64,true));
        check(!MobiMindContract.verify(receipt(),terminal(),tokens(),broken,RAW,X,0).isEmpty(),"full weight hash byte count cannot be replaced by a sample");
        r=receipt();r.put("mnn_context",map("status",2,"output_token_count",256));check(!verify(r).isEmpty(),"token-limit status is not EOS completion");
        check(!MobiMindContract.verify(receipt(),terminal(),tokens(),models(),RAW,X,143).isEmpty(),"nonzero owned exit cannot qualify");
        Map<String,Object> badModel=models();badModel.remove("llm.mnn.weight");check(!MobiMindContract.verify(receipt(),terminal(),tokens(),badModel,RAW,X,0).isEmpty(),"all eleven pinned file receipts required");
        check(!MobiMindContract.verify(receipt(),terminal(),tokens(),models(),new byte[]{(byte)0xff},X,0).isEmpty(),"invalid raw UTF8 rejected");
        Map<String,Object> parsed=MobiMindContract.jsonObject("{\"a\":[true,false,null,1,1.5],\"b\":\"😀\"}".getBytes(StandardCharsets.UTF_8));check(parsed.size()==2,"strict JSON valid fixture");
        String[] bad={"{\"a\":1,\"a\":2}","{\"a\":1,\"\\u0061\":2}","{a:1}","{\"a\":NaN}","{\"a\":1e999}","{\"a\":01}","{\"a\":true,}","{\"a\":[1,]}","{} garbage","{\"a\":\"\\uD800\"}","{\"a\":\"\\x00\"}","[]"};
        for(String value:bad){boolean rejected=false;try{MobiMindContract.jsonObject(value.getBytes(StandardCharsets.UTF_8));}catch(Exception expected){rejected=true;}check(rejected,"strict JSON rejects malformed receipt");}
        System.out.println("MobiMindContractHostTest assertions="+assertions);
    }
}
