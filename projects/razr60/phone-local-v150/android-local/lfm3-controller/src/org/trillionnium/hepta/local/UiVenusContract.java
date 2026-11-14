package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Evidence binding for the fixed VLM core. This does not parse or execute model actions. */
public final class UiVenusContract {
    private UiVenusContract() {}
    public static final class Expected {
        public final String id,files,run,runtime;
        public final int uid,parent;
        public final UiVenusInputContract.Inputs inputs;
        public Expected(String id,int uid,int parent,String files,String runtime,UiVenusInputContract.Inputs inputs){
            if(id==null||!id.matches("[0-9a-f]{32}")||uid<10000||parent<=1||files==null||!files.startsWith("/data/")
                    ||files.endsWith("/")||runtime==null||!runtime.startsWith("/data/app/")||runtime.endsWith("/")||inputs==null)
                throw new IllegalArgumentException("invalid App VLM expected identity");
            this.id=id;this.uid=uid;this.parent=parent;this.files=files;this.runtime=runtime;this.inputs=inputs;
            run=files+"/ui-venus-runs/"+id;
        }
    }
    public static List<String> verifyCore(Map<String,Object> r,Map<String,byte[]> artifacts,Expected x,int exit){
        List<String> errors=new ArrayList<String>();
        check(errors,exit==0,"process_exit");equal(errors,r,"schema","hepta.ui-venus-vlm-once.result.v1");
        equal(errors,r,"request_id",x.id);number(errors,r,"uid",x.uid);number(errors,r,"euid",x.uid);number(errors,r,"parent_pid",x.parent);
        check(errors,integer(r.get("pid"))>1,"native_pid");equal(errors,r,"sdk_source_commit",UiVenusPins.SDK_COMMIT);
        check(errors,"0.10.0".equals(r.get("sdk_version"))||"v0.10.0".equals(r.get("sdk_version")),"sdk_version");
        equal(errors,r,"mode","vlm");equal(errors,r,"runtime","llama_cpp");equal(errors,r,"model_profile",UiVenusPins.PROFILE);
        equal(errors,r,"model_repository",UiVenusPins.MODEL_REPO);equal(errors,r,"model_revision",UiVenusPins.MODEL_REVISION);
        equal(errors,r,"model_architecture","qwen35");equal(errors,r,"tokenizer_pre","qwen35");equal(errors,r,"gguf_template_sha256",UiVenusPins.TEMPLATE_SHA);
        equal(errors,r,"official_mobile_revision",UiVenusPins.OFFICIAL_REVISION);
        equal(errors,r,"official_mobile_system_template_sha256",UiVenusPins.OFFICIAL_SYSTEM_SHA);
        equal(errors,r,"owner_embedded_system_suffix_sha256",x.inputs.ownerSha);
        Object weightValue=r.get("weights");List<?> weights=weightValue instanceof List?(List<?>)weightValue:java.util.Collections.emptyList();
        check(errors,weights.size()==2,"two_weight_bindings");UiVenusPins.FilePin[] pins=UiVenusPins.models();
        for(int i=0;i<Math.min(2,weights.size());i++){
            Map<String,Object> row=MobiMindContract.object(weights.get(i));UiVenusPins.FilePin p=pins[i];
            equal(errors,row,"name",p.name);equal(errors,row,"path",x.files+"/"+UiVenusPins.MODEL_DIRECTORY+"/"+p.name);
            number(errors,row,"expected_bytes",p.bytes);number(errors,row,"bytes_hashed",p.bytes);
            equal(errors,row,"expected_sha256",p.sha256);equal(errors,row,"actual_full_sha256",p.sha256);
            equal(errors,row,"verified",true);equal(errors,row,"metadata_unchanged",true);
            check(errors,row.get("fd_path") instanceof String&&((String)row.get("fd_path")).matches("/proc/self/fd/[0-9]+"),"weight_fd_path");
            check(errors,"armv8-sha2".equals(row.get("sha_backend"))||"portable".equals(row.get("sha_backend")),"weight_sha_backend");
        }
        Map<String,Object> in=MobiMindContract.object(r.get("input_sha256"));
        check(errors,in.size()==4&&in.containsKey("grammar")&&in.get("grammar")==null,"input_hash_membership");
        equal(errors,in,"prompt",x.inputs.promptSha);equal(errors,in,"system",x.inputs.systemSha);equal(errors,in,"image",x.inputs.imageSha);
        equal(errors,r,"input_metadata_unchanged",true);
        for(String key:new String[]{"generation_complete","raw_text_utf8","vision_capability_query_attempted","supports_vision",
                "chat_template_enable_thinking","prompt_sidecars_complete","text_only_necessary_budget_passed","sdk_reported_total_within_requested_context"})equal(errors,r,key,true);
        for(String key:new String[]{"raw_text_truncated","automatic_retry","deadline_observed","callback_limit_observed","image_resize_by_worker",
                "cpu_neural_retry_allowed","speculative_decoding","full_multimodal_input_qualified","no_context_shift_proven",
                "pre_generation_multimodal_token_count_available","diagnostic_text_ids_passed_to_vlm","actions_dispatched",
                "ordinary_app_qualified","native_tools_argument","handwritten_grammar","sampler_auto_grammar_used",
                "vision_preprocess_shape_proven","per_operator_backend_coverage_proven"})equal(errors,r,key,false);
        equal(errors,r,"worker_outcome","completed");check(errors,r.containsKey("error")&&r.get("error")==null,"native_error");
        number(errors,r,"worker_exit_status_planned",0);equal(errors,r,"stop_reason","eos");equal(errors,r,"raw_text_source","sdk_full_text");
        equal(errors,r,"compute_requested","npu");equal(errors,r,"device_resolved","HTP0");
        check(errors,r.containsKey("device_warning")&&r.get("device_warning")==null,"device_warning");
        check(errors,integer(r.get("n_gpu_layers_create"))!=Long.MIN_VALUE&&integer(r.get("n_gpu_layers_create"))!=0,"n_gpu_layers_create");
        equal(errors,r,"vit_device_requested","GPUOpenCL");number(errors,r,"vision_capability_query_rc",0);number(errors,r,"image_count",1);
        number(errors,r,"image_width_original",x.inputs.width);number(errors,r,"image_height_original",x.inputs.height);
        number(errors,r,"n_ctx_create",UiVenusPins.CONTEXT);number(errors,r,"max_tokens",UiVenusPins.MAX_TOKENS);
        number(errors,r,"generate_attempt_count",1);number(errors,r,"history_turns",0);number(errors,r,"signal_observed",0);
        Map<String,Object> sampler=MobiMindContract.object(r.get("sampler_requested"));
        decimal(errors,sampler,"temperature",0.1);decimal(errors,sampler,"top_p",0.95);number(errors,sampler,"top_k",40);
        decimal(errors,sampler,"min_p",0.05);decimal(errors,sampler,"repetition_penalty",1.05);
        decimal(errors,sampler,"presence_penalty",0);decimal(errors,sampler,"frequency_penalty",0.3);number(errors,sampler,"seed",42);
        Map<String,Object> config=MobiMindContract.object(r.get("model_config_requested"));number(errors,config,"n_batch",256);number(errors,config,"n_ubatch",128);number(errors,config,"n_seq_max",1);
        Map<String,Object> rc=MobiMindContract.object(r.get("sdk_rc"));
        for(String key:new String[]{"resolve","set_log_level","init","create","template","generate","destroy","deinit"})number(errors,rc,key,0);
        Map<String,Object> profile=MobiMindContract.object(r.get("profile"));long generated=integer(profile.get("generated_tokens")),prompt=integer(profile.get("prompt_tokens"));
        check(errors,generated>0&&generated<UiVenusPins.MAX_TOKENS&&prompt>0&&prompt<=UiVenusPins.CONTEXT
                &&prompt+generated<=UiVenusPins.CONTEXT,"SDK_post_run_token_counts");
        number(errors,r,"sdk_reported_token_total",prompt+generated);check(errors,integer(profile.get("media_time_us"))>0,"media_time_observed");
        byte[] raw=artifacts.get("raw.txt");check(errors,raw!=null&&raw.length>0&&raw.length<=1048576,"raw_size");
        if(raw!=null){number(errors,r,"raw_text_bytes",raw.length);equal(errors,r,"raw_text_sha256",MobiMindContract.sha(raw));try{MobiMindContract.utf8(raw);}catch(Exception e){errors.add("raw_utf8");}}
        Map<String,Object> side=MobiMindContract.object(r.get("prompt_sidecar_sha256"));
        for(String name:new String[]{"formatted-prompt.txt","gguf-chat-template.jinja","diagnostic-text-only-token-ids.le32","sdk-generation-prefix.txt"}){
            byte[] bytes=artifacts.get(name);check(errors,bytes!=null,"missing_sidecar:"+name);if(bytes!=null)equal(errors,side,name,MobiMindContract.sha(bytes));
        }
        byte[] template=artifacts.get("gguf-chat-template.jinja"),formatted=artifacts.get("formatted-prompt.txt"),ids=artifacts.get("diagnostic-text-only-token-ids.le32");
        if(template!=null)check(errors,template.length==7740&&MobiMindContract.sha(template).equals(UiVenusPins.TEMPLATE_SHA),"embedded_template");
        if(formatted!=null){equal(errors,r,"formatted_prompt_sha256",MobiMindContract.sha(formatted));try{MobiMindContract.utf8(formatted);}catch(Exception e){errors.add("formatted_utf8");}}
        long diagnostic=integer(r.get("diagnostic_text_only_tokens"));
        check(errors,diagnostic>0&&diagnostic+UiVenusPins.MAX_TOKENS+256<=UiVenusPins.CONTEXT,"text_only_necessary_budget");
        if(ids!=null){check(errors,ids.length==4*diagnostic,"diagnostic_ID_count");if(ids.length%4==0)for(int i=0;i<ids.length;i+=4){
            long id=(ids[i]&255L)|(ids[i+1]&255L)<<8|(ids[i+2]&255L)<<16|(ids[i+3]&255L)<<24;
            if(id>=248320){errors.add("diagnostic_ID_vocabulary");break;}
        }}
        return errors;
    }
    static void check(List<String> e,boolean ok,String key){if(!ok)e.add(key);}
    static void equal(List<String> e,Map<String,Object> m,String k,Object v){check(e,v.equals(m.get(k)),k);}
    static void number(List<String> e,Map<String,Object> m,String k,long v){check(e,integer(m.get(k))==v,k);}
    static long integer(Object v){return v instanceof Long||v instanceof Integer?((Number)v).longValue():Long.MIN_VALUE;}
    private static void decimal(List<String> e,Map<String,Object> m,String k,double v){Object n=m.get(k);check(e,n instanceof Number&&Math.abs(((Number)n).doubleValue()-v)<0.000001,k);}
}
