import org.trillionnium.hepta.local.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Synthetic receipt mutations. A pass is not native inference, GPU/NPU offload, or GUI success. */
public final class UiVenusContractHostTest {
    static int assertions;static UiVenusContract.Expected x;static Map<String,byte[]> artifacts;
    static void yes(boolean value){assertions++;if(!value)throw new AssertionError();}
    static Map<String,Object> map(Object... pairs){Map<String,Object> m=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)m.put((String)pairs[i],pairs[i+1]);return m;}
    static Map<String,Object> receipt(){
        Map<String,Object> r=map("schema","hepta.ui-venus-vlm-once.result.v1","request_id",x.id,"uid",x.uid,"euid",x.uid,"pid",12346,"parent_pid",x.parent,
            "sdk_source_commit",UiVenusPins.SDK_COMMIT,"sdk_version","0.10.0","mode","vlm","runtime","llama_cpp","model_profile",UiVenusPins.PROFILE,
            "model_repository",UiVenusPins.MODEL_REPO,"model_revision",UiVenusPins.MODEL_REVISION,"model_architecture","qwen35","tokenizer_pre","qwen35",
            "gguf_template_sha256",UiVenusPins.TEMPLATE_SHA,"official_mobile_revision",UiVenusPins.OFFICIAL_REVISION,"official_mobile_system_template_sha256",UiVenusPins.OFFICIAL_SYSTEM_SHA,
            "owner_embedded_system_suffix_sha256",x.inputs.ownerSha);
        List<Object> weights=new ArrayList<Object>();for(UiVenusPins.FilePin p:UiVenusPins.models())weights.add(map("name",p.name,"path",x.files+"/"+UiVenusPins.MODEL_DIRECTORY+"/"+p.name,
            "expected_bytes",p.bytes,"bytes_hashed",p.bytes,"expected_sha256",p.sha256,"actual_full_sha256",p.sha256,"verified",true,"metadata_unchanged",true,"fd_path","/proc/self/fd/3","sha_backend","armv8-sha2"));
        r.put("weights",weights);r.put("input_sha256",map("prompt",x.inputs.promptSha,"system",x.inputs.systemSha,"image",x.inputs.imageSha,"grammar",null));r.put("input_metadata_unchanged",true);
        for(String key:new String[]{"generation_complete","raw_text_utf8","vision_capability_query_attempted","supports_vision","chat_template_enable_thinking","prompt_sidecars_complete","text_only_necessary_budget_passed","sdk_reported_total_within_requested_context"})r.put(key,true);
        for(String key:new String[]{"raw_text_truncated","automatic_retry","deadline_observed","callback_limit_observed","image_resize_by_worker","cpu_neural_retry_allowed","speculative_decoding","full_multimodal_input_qualified","no_context_shift_proven","pre_generation_multimodal_token_count_available","diagnostic_text_ids_passed_to_vlm","actions_dispatched","ordinary_app_qualified","native_tools_argument","handwritten_grammar","sampler_auto_grammar_used","vision_preprocess_shape_proven","per_operator_backend_coverage_proven"})r.put(key,false);
        r.putAll(map("worker_outcome","completed","error",null,"worker_exit_status_planned",0,"stop_reason","eos","raw_text_source","sdk_full_text","compute_requested","npu","device_resolved","HTP0","device_warning",null,"n_gpu_layers_create",99,
            "vit_device_requested","GPUOpenCL","vision_capability_query_rc",0,"image_count",1,"image_width_original",x.inputs.width,"image_height_original",x.inputs.height,"n_ctx_create",8192,"max_tokens",1024,"generate_attempt_count",1,"history_turns",0,"signal_observed",0));
        r.put("sampler_requested",map("temperature",0.1,"top_p",0.95,"top_k",40,"min_p",0.05,"repetition_penalty",1.05,"presence_penalty",0.0,"frequency_penalty",0.3,"seed",42));
        r.put("model_config_requested",map("n_batch",256,"n_ubatch",128,"n_seq_max",1));Map<String,Object> rc=new LinkedHashMap<String,Object>();for(String k:new String[]{"resolve","set_log_level","init","create","template","generate","destroy","deinit"})rc.put(k,0);r.put("sdk_rc",rc);
        r.put("profile",map("generated_tokens",10,"prompt_tokens",600,"media_time_us",1));r.put("sdk_reported_token_total",610);
        r.put("raw_text_bytes",artifacts.get("raw.txt").length);r.put("raw_text_sha256",MobiMindContract.sha(artifacts.get("raw.txt")));
        Map<String,Object> side=new LinkedHashMap<String,Object>();for(String n:new String[]{"formatted-prompt.txt","gguf-chat-template.jinja","diagnostic-text-only-token-ids.le32","sdk-generation-prefix.txt"})side.put(n,MobiMindContract.sha(artifacts.get(n)));r.put("prompt_sidecar_sha256",side);
        r.put("formatted_prompt_sha256",MobiMindContract.sha(artifacts.get("formatted-prompt.txt")));r.put("diagnostic_text_only_tokens",1);return r;
    }
    public static void main(String[] args)throws Exception{
        Path p=Paths.get("tests/ui-venus");UiVenusInputContract.Inputs inputs=UiVenusInputContract.verify(Files.readAllBytes(p.resolve("FIXTURE.json")),Files.readAllBytes(p.resolve("owner.txt")),Files.readAllBytes(p.resolve("prompt.txt")),Files.readAllBytes(p.resolve("system.txt")),Files.readAllBytes(p.resolve("screen.png")),Files.readAllBytes(Paths.get("provenance/ui-venus-app-r1/official-system-template.txt")));
        x=new UiVenusContract.Expected("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",10481,12345,"/data/user/0/org.trillionnium.hepta.local/files","/data/app/test/lib/arm64",inputs);
        artifacts=new LinkedHashMap<String,byte[]>();artifacts.put("raw.txt","synthetic text, not an action".getBytes(StandardCharsets.UTF_8));artifacts.put("formatted-prompt.txt","synthetic test only".getBytes(StandardCharsets.UTF_8));
        artifacts.put("gguf-chat-template.jinja",Files.readAllBytes(Paths.get("provenance/ui-venus-app-r1/gguf-chat-template.jinja")));artifacts.put("diagnostic-text-only-token-ids.le32",new byte[]{1,0,0,0});artifacts.put("sdk-generation-prefix.txt",new byte[0]);
        List<String> good=UiVenusContract.verifyCore(receipt(),artifacts,x,0);if(!good.isEmpty())throw new AssertionError(good.toString());yes(true);
        for(Map.Entry<String,Object> n:map("schema","other","uid",2000,"euid",2000,"parent_pid",12347,"model_architecture","qwen3vl","owner_embedded_system_suffix_sha256","wrong",
            "generation_complete",false,"stop_reason","max_tokens","raw_text_truncated",true,"input_metadata_unchanged",false,"ordinary_app_qualified",true,"actions_dispatched",true,"device_resolved","CPU",
            "n_gpu_layers_create",0,"vit_device_requested","CPU","generate_attempt_count",2,"n_ctx_create",4096,"history_turns",1,"diagnostic_text_only_tokens",1.0,"sdk_reported_token_total",611,
            "full_multimodal_input_qualified",true,"no_context_shift_proven",true,"diagnostic_text_ids_passed_to_vlm",true,"pre_generation_multimodal_token_count_available",true,"deadline_observed",true,"error","failed").entrySet()){
            Map<String,Object> r=receipt();r.put(n.getKey(),n.getValue());yes(!UiVenusContract.verifyCore(r,artifacts,x,0).isEmpty());
        }
        Map<String,Object> bad=receipt();bad.put("weights",Collections.emptyList());yes(!UiVenusContract.verifyCore(bad,artifacts,x,0).isEmpty());
        bad=receipt();bad.put("input_sha256",map("prompt",inputs.promptSha,"system",inputs.systemSha,"image",inputs.imageSha));yes(!UiVenusContract.verifyCore(bad,artifacts,x,0).isEmpty());
        bad=receipt();bad.put("profile",map("generated_tokens",1024,"prompt_tokens",600,"media_time_us",1));yes(!UiVenusContract.verifyCore(bad,artifacts,x,0).isEmpty());
        bad=receipt();bad.put("profile",map("generated_tokens",10,"prompt_tokens",8190,"media_time_us",1));yes(!UiVenusContract.verifyCore(bad,artifacts,x,0).isEmpty());
        for(String name:new ArrayList<String>(artifacts.keySet())){byte[] old=artifacts.remove(name);yes(!UiVenusContract.verifyCore(receiptWithMissingSafe(name,old),artifacts,x,0).isEmpty());artifacts.put(name,old);}
        yes(!UiVenusContract.verifyCore(receipt(),artifacts,x,143).isEmpty());
        System.out.println("UI-Venus core contracts passed: "+assertions+"; synthetic receipts, not model qualification");
    }
    static Map<String,Object> receiptWithMissingSafe(String name,byte[] bytes){artifacts.put(name,bytes);Map<String,Object> r=receipt();artifacts.remove(name);return r;}
}
