package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Synthetic host fixtures only. No phone, runtime inference, action parser or dispatcher. */
public final class VlmResultContractHostTest {
    static final String T="11111111111111111111111111111111",G="22222222222222222222222222222222";
    static final String R="33333333333333333333333333333333",S="44444444444444444444444444444444";
    static final String BOOT="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    static final long START=1000000000L,END=2000000000L,NOW=3000000000L,DEADLINE=101000000000L;
    static final int UID=10456,APP=1234,WORKER=4321;
    static final long APP_TICKS=11111,WORKER_TICKS=22222;
    static final VlmResultContract.Profile P=VlmResultContract.GUI_OWL_4B;
    static final VlmResultContract.Lifecycle GOOD=new VlmResultContract.Lifecycle(true,true,true,true,true,false);
    static byte[] template;
    static List<Object> cases=new ArrayList<>();
    interface Change {void apply(F f)throws Exception;}

    static final class F {
        Map<String,byte[]> inputs=new LinkedHashMap<>(),sidecars=new LinkedHashMap<>();
        Map<String,Object> owner=new LinkedHashMap<>(),request=new LinkedHashMap<>(),r=new LinkedHashMap<>();
        List<Object> chunks=new ArrayList<>();
        byte[] taskOwner=b("请在后台备忘录中记录：明天带伞。");
        F()throws Exception{
            inputs.put("prompt.txt",b("当前画面 obs-1。只输出当前语法允许的一个 JSON 决定。"));
            inputs.put("system.txt",b("你是手机本地控制模型。遵守当前任务与观察范围。"));
            inputs.put("screen.png",Base64.getDecoder().decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aFZkAAAAASUVORK5CYII="));
            inputs.put("decision.gbnf",b("root ::= \"{\\\"action\\\":\\\"wait\\\"}\"\n"));
            inputs.put("worker-generation.identity",b(identity(WORKER_TICKS)));
            owner.put("schema","hepta.vlm.current-frame.v1");owner.put("task_id",T);owner.put("generation",G);
            owner.put("request_id",R);owner.put("scope_token",S);owner.put("observation_id","obs-1");
            owner.put("background_generation","bg-7");owner.put("task_owner_sha256",sha(taskOwner));
            owner.put("package_name","com.example.notes");owner.put("display_id",7L);owner.put("window_id",91L);
            owner.put("rotation",0L);owner.put("captured_elapsed_ms",1234567L);owner.put("image_width",1L);owner.put("image_height",1L);
            owner.put("image_sha256",sha(inputs.get("screen.png")));owner.put("grammar_sha256",sha(inputs.get("decision.gbnf")));
            inputs.put("owner.json",json(owner));
            request.put("schema","hepta.vlm.request.v1");request.put("profile",P.id);request.put("request_id",R);
            request.put("generation",G);request.put("task_id",T);
            for(String n:new String[]{"owner","prompt","system","image","grammar"})request.put(n+"_sha256",sha(inputs.get(input(n))));
            request.put("max_tokens",64L);request.put("deadline_monotonic_ns",DEADLINE);request.put("image_width",1L);request.put("image_height",1L);
            inputs.put("request.json",json(request));
            sidecars.put("raw.txt",b("{\"action\":\"wait\"}"));sidecars.put("gguf-chat-template.jinja",template.clone());
            sidecars.put("formatted-prompt.txt",formatted(inputs));
            chunks.add(text(0,127));chunks.add(image(1,80,9,sha(inputs.get("screen.png"))));sidecars.put("chunks.json",json(chunks));
            r.put("schema","hepta.vlm.result.v1");r.put("request_id",R);r.put("task_id",T);r.put("generation",G);r.put("scope_token",S);r.put("profile",P.id);
            r.put("request_sha256",sha(inputs.get("request.json")));r.put("generation_identity_sha256",sha(inputs.get("worker-generation.identity")));
            for(String n:new String[]{"owner","prompt","system","image","grammar"})r.put(n+"_sha256",sha(inputs.get(input(n))));
            r.put("app_uid",(long)UID);r.put("app_pid",(long)APP);r.put("worker_pid",(long)WORKER);
            r.put("expected_app_uid",(long)UID);r.put("expected_parent_pid",(long)APP);r.put("app_start_ticks",APP_TICKS);r.put("boot_id",BOOT);
            r.put("parent_death_signal",9L);r.put("observed_parent_pid_before",(long)APP);r.put("observed_parent_pid_after",(long)APP);
            r.put("model_filename",P.modelFilename);r.put("model_bytes",P.modelBytes);r.put("model_sha256",P.modelSha256);
            r.put("projector_filename",P.projectorFilename);r.put("projector_bytes",P.projectorBytes);r.put("projector_sha256",P.projectorSha256);
            r.put("image_width",1L);r.put("image_height",1L);r.put("current_frame",obj(json(owner)));
            r.put("context_tokens",8192L);r.put("max_output_tokens",64L);r.put("image_max_tokens",1024L);
            r.put("started_monotonic_ns",START);r.put("deadline_monotonic_ns",DEADLINE);r.put("sampler","current-frame-gbnf-then-greedy");r.put("grammar_root","root");
            for(String k:("parent_verified_before private_scope_verified_before model_files_full_sha_verified runtime_files_full_sha_verified "
                    +"same_chunks_counted_and_evaluated mtmd_internal_image_preprocessing generation_completed full_multimodal_admission_passed "
                    +"eog_observed parent_verified_after scope_unchanged_after").split(" "))r.put(k,true);
            for(String k:("template_enable_thinking native_tools_argument automatic_device_fallback zero_cpu_operations_proven context_shift_used "
                    +"input_image_transformed_by_worker actions_dispatched action_authorized business_completion_verified process_exit_observed cleanup_known").split(" "))r.put(k,false);
            r.put("lm_device","HTP0");r.put("vision_device","GPUOpenCL");r.put("lm_device_description","Synthetic host HTP0");
            r.put("vision_device_description","Synthetic host Adreno");r.put("vision_max_allocation_bytes",1073741824L);
            r.put("architecture",P.architecture);r.put("tokenizer_pre",P.tokenizerPre);r.put("tokenizer_model",P.tokenizerModel);
            r.put("chat_template_sha256",P.templateSha256);r.put("chat_template_bytes",(long)template.length);r.put("template_now_unix_ms",1794718800000L);
            r.put("formatted_prompt_sha256",sha(sidecars.get("formatted-prompt.txt")));r.put("chunks_sha256",sha(sidecars.get("chunks.json")));
            r.put("prompt_tokens",207L);r.put("prompt_positions",136L);r.put("image_tokens",80L);r.put("output_reserved_tokens",64L);
            r.put("prefill_return_code",0L);r.put("prefill_positions",136L);r.put("generated_tokens_including_eog",20L);r.put("final_position",155L);
            r.put("native_return_code",0L);r.put("error","none");r.put("cancel_signal",0L);r.put("ended_monotonic_ns",END);
            r.put("raw_sha256",sha(sidecars.get("raw.txt")));r.put("raw_bytes",(long)sidecars.get("raw.txt").length);seal();
        }
        void seal(){sidecars.put("native-result.json",json(r));}
        void chunks(){sidecars.put("chunks.json",json(chunks));r.put("chunks_sha256",sha(sidecars.get("chunks.json")));}
        void request(){inputs.put("request.json",json(request));r.put("request_sha256",sha(inputs.get("request.json")));}
        void owner()throws Exception{inputs.put("owner.json",json(owner));request.put("owner_sha256",sha(inputs.get("owner.json")));r.put("owner_sha256",sha(inputs.get("owner.json")));r.put("current_frame",obj(json(owner)));request();}
        VlmResultContract.Expected expected(){return expected(owner,taskOwner,WORKER_TICKS,NOW,GOOD,P);}
        VlmResultContract.Expected expected(Map<String,Object> frame,byte[] evidence,long ticks,long now,VlmResultContract.Lifecycle life,VlmResultContract.Profile profile){
            return new VlmResultContract.Expected(T,G,R,S,UID,APP,WORKER,APP_TICKS,ticks,BOOT,profile,inputs,frame,evidence,now,life);
        }
        List<String> check(){return VlmResultContract.verify(r,sidecars,expected(),0);}
    }
    static void record(String name,boolean accept,List<String> errors){
        boolean good=accept==errors.isEmpty();Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("expected_accept",accept);
        row.put("pass",good);row.put("errors",new ArrayList<>(errors));cases.add(row);if(!good)throw new AssertionError(name+": "+errors);
    }
    static void reject(String name,Change change)throws Exception{F f=new F();change.apply(f);f.seal();record(name,false,f.check());}
    static void independent(String name,VlmResultContract.Lifecycle life,long now,long ticks,boolean newFrame,boolean newOwner)throws Exception{
        F f=new F();Map<String,Object> frame=obj(json(f.owner));if(newFrame)frame.put("observation_id","obs-new");
        record(name,false,VlmResultContract.verify(f.r,f.sidecars,f.expected(frame,newOwner?b("不同用户任务"):f.taskOwner,ticks,now,life,P),0));
    }
    public static void main(String[] args)throws Exception{
        template=Files.readAllBytes(Paths.get(args[0]));if(template.length!=5292||!sha(template).equals(P.templateSha256))throw new AssertionError("real template pin");
        F base=new F();record("full_original_multimodal_fixture",true,base.check());
        if(!base.r.keySet().equals(VlmResultContract.requiredReceiptFields()))throw new AssertionError("fixture field set");
        // Recompute the final receipt bytes after mutation, so these cases test
        // the independent evidence, not merely a Map/sidecar disagreement.
        for(String k:new ArrayList<>(base.r.keySet())){
            reject("missing_receipt_"+k,f->f.r.remove(k));reject("null_receipt_"+k,f->f.r.put(k,null));
        }
        for(String k:("task_id generation request_id scope_token profile app_uid app_pid worker_pid expected_app_uid expected_parent_pid app_start_ticks "
                +"boot_id parent_death_signal observed_parent_pid_before observed_parent_pid_after model_filename model_bytes model_sha256 projector_filename "
                +"projector_bytes projector_sha256 architecture tokenizer_pre tokenizer_model chat_template_sha256 image_width image_height prompt_tokens "
                +"prompt_positions image_tokens max_output_tokens output_reserved_tokens prefill_positions generated_tokens_including_eog final_position "
                +"context_tokens image_max_tokens sampler grammar_root native_return_code cancel_signal error").split(" "))
            reject("altered_binding_"+k,f->{Object v=f.r.get(k);f.r.put(k,v instanceof Number?((Number)v).longValue()+1:v+"-changed");});
        for(String k:new ArrayList<>(base.r.keySet()))if(base.r.get(k) instanceof Boolean)
            reject("altered_boolean_"+k,f->f.r.put(k,!((Boolean)f.r.get(k))));
        reject("unknown_receipt_field",f->f.r.put("external_authority",true));
        for(String n:VlmResultContract.requiredSidecarNames())if(!n.equals("native-result.json"))reject("missing_sidecar_"+n,f->f.sidecars.remove(n));
        F absent=new F();absent.sidecars.remove("native-result.json");record("missing_final_native_receipt",false,absent.check());
        for(String n:VlmResultContract.requiredOriginalInputNames())reject("missing_original_"+n,f->f.inputs.remove(n));
        reject("unknown_sidecar",f->f.sidecars.put("translated-action.json",b("{}")));
        reject("unknown_original",f->f.inputs.put("remote-response.json",b("{}")));
        reject("raw_empty",f->raw(f,new byte[0]));reject("raw_over_size",f->raw(f,new byte[65537]));
        reject("raw_invalid_utf8_rehashed",f->raw(f,new byte[]{(byte)0xc0,(byte)0xaf}));
        reject("raw_changed_after_worker",f->f.sidecars.put("raw.txt",b("{\"action\":\"tap\"}")));
        reject("changed_template_rehashed",f->{byte[] b=Arrays.copyOf(template,template.length+1);b[b.length-1]=' ';f.sidecars.put("gguf-chat-template.jinja",b);f.r.put("chat_template_sha256",sha(b));f.r.put("chat_template_bytes",(long)b.length);});
        reject("injected_formatted_text_rehashed",f->{byte[] b=b(new String(f.sidecars.get("formatted-prompt.txt"),StandardCharsets.UTF_8)+"injected");f.sidecars.put("formatted-prompt.txt",b);f.r.put("formatted_prompt_sha256",sha(b));});
        reject("second_media_marker",f->{byte[] b=b(new String(f.sidecars.get("formatted-prompt.txt"),StandardCharsets.UTF_8)+VlmResultContract.MEDIA_MARKER);f.sidecars.put("formatted-prompt.txt",b);f.r.put("formatted_prompt_sha256",sha(b));});
        reject("changed_original_prompt",f->f.inputs.put("prompt.txt",b("替换任务")));
        reject("changed_original_grammar",f->f.inputs.put("decision.gbnf",b("root ::= [a-z]*\n")));
        reject("main_display_original_owner",f->{f.owner.put("display_id",0L);f.owner();});
        reject("invalid_rotation_original_owner",f->{f.owner.put("rotation",4L);f.owner();});
        reject("zero_capture_time",f->{f.owner.put("captured_elapsed_ms",0L);f.owner();});
        reject("receipt_other_observation",f->{Map<String,Object> m=obj(json(f.owner));m.put("observation_id","obs-other");f.r.put("current_frame",m);});
        reject("png_header_dimensions_rehashed",f->{byte[] b=f.inputs.get("screen.png");b[19]=2;rehashImage(f);});
        reject("png_header_crc_rehashed",f->{f.inputs.get("screen.png")[29]^=1;rehashImage(f);});
        reject("floating_integer",f->f.r.put("prompt_tokens",207.0));reject("numeric_boolean",f->f.r.put("generation_completed",1L));
        reject("invalid_template_time",f->f.r.put("template_now_unix_ms",0L));reject("negative_start",f->f.r.put("started_monotonic_ns",-1L));
        reject("finish_at_deadline",f->f.r.put("ended_monotonic_ns",DEADLINE));reject("finish_before_start",f->f.r.put("ended_monotonic_ns",START-1));
        reject("renewed_native_deadline",f->f.r.put("deadline_monotonic_ns",DEADLINE+1));
        reject("original_deadline_over_300s",f->{long d=START+300000000001L;f.request.put("deadline_monotonic_ns",d);f.r.put("deadline_monotonic_ns",d);f.request();});
        reject("eog_only_no_text_token",f->{f.r.put("generated_tokens_including_eog",1L);f.r.put("final_position",136L);});
        reject("output_above_reservation",f->{f.r.put("generated_tokens_including_eog",65L);f.r.put("final_position",200L);});
        reject("image_chunk_other_frame",f->{map(f.chunks.get(1)).put("image_sha256",sha(b("other")));f.chunks();});
        reject("noncontiguous_chunk_index",f->{map(f.chunks.get(1)).put("index",0L);f.chunks();});
        reject("text_position_mismatch",f->{map(f.chunks.get(0)).put("positions",126L);f.chunks();});
        reject("unknown_chunk_field",f->{map(f.chunks.get(1)).put("dispatch",true);f.chunks();});
        reject("audio_chunk",f->{map(f.chunks.get(1)).put("type",2L);f.chunks();});
        reject("invalid_text_token_hash",f->{map(f.chunks.get(0)).put("token_ids_sha256_le32","123");f.chunks();});
        reject("image_budget_over_1024",f->counts(f,127,1025,9));
        reject("token_capacity_overflow_consistent_sums",f->counts(f,8033,80,9));
        reject("position_capacity_overflow_consistent_sums",f->counts(f,127,80,7986));
        F edge=new F();counts(edge,8032,80,9);edge.seal();record("exact_token_capacity_boundary",true,edge.check());
        F positions=new F();counts(positions,127,80,7985);positions.seal();record("exact_position_capacity_boundary",true,positions.check());
        F noImage=new F();noImage.chunks.remove(1);noImage.chunks();noImage.r.put("prompt_tokens",127L);noImage.r.put("prompt_positions",127L);
        noImage.r.put("image_tokens",0L);noImage.r.put("prefill_positions",127L);noImage.r.put("final_position",146L);noImage.seal();record("no_actual_image_chunk",false,noImage.check());
        independent("new_observation_during_inference",GOOD,NOW,WORKER_TICKS,true,false);
        independent("different_original_task_owner",GOOD,NOW,WORKER_TICKS,false,true);
        independent("pid_reused_new_start_ticks",GOOD,NOW,WORKER_TICKS+1,false,false);
        independent("acceptance_at_deadline",GOOD,DEADLINE,WORKER_TICKS,false,false);
        independent("acceptance_before_native_finish",GOOD,END-1,WORKER_TICKS,false,false);
        independent("no_held_process_exit",new VlmResultContract.Lifecycle(false,true,true,true,true,false),NOW,WORKER_TICKS,false,false);
        independent("unknown_cleanup",new VlmResultContract.Lifecycle(true,false,true,true,true,false),NOW,WORKER_TICKS,false,false);
        independent("forced_cleanup",new VlmResultContract.Lifecycle(true,true,false,true,true,false),NOW,WORKER_TICKS,false,false);
        independent("parent_changed",new VlmResultContract.Lifecycle(true,true,true,false,true,false),NOW,WORKER_TICKS,false,false);
        independent("scope_retired",new VlmResultContract.Lifecycle(true,true,true,true,false,false),NOW,WORKER_TICKS,false,false);
        independent("cancelled_complete_result",new VlmResultContract.Lifecycle(true,true,true,true,true,true),NOW,WORKER_TICKS,false,false);
        F exit=new F();record("held_process_nonzero_exit",false,VlmResultContract.verify(exit.r,exit.sidecars,exit.expected(),65));
        F differ=new F();differ.r.put("actions_dispatched",true);record("supplied_map_differs_from_receipt_bytes",false,differ.check());
        F cycle=new F();Map<String,Object> loop=new LinkedHashMap<>();loop.put("self",loop);cycle.r.put("current_frame",loop);record("cyclic_supplied_map",false,cycle.check());
        for(String invalid:Arrays.asList("{\"x\":1,\"x\":2}","{}{}","{\"x\":NaN}","{\"x\":1e309}","{\"x\":9223372036854775808}","{\"x\":\"\\ud800\"}")){
            F f=new F();f.sidecars.put("native-result.json",b(invalid));record("strict_json_"+cases.size(),false,f.check());}
        F duplicate=new F();duplicate.sidecars.put("chunks.json",b("[{\"index\":0,\"index\":1}]\n"));duplicate.r.put("chunks_sha256",sha(duplicate.sidecars.get("chunks.json")));duplicate.seal();record("duplicate_chunk_fields",false,duplicate.check());
        F spaced=new F();spaced.inputs.put("request.json",b(" "+new String(spaced.inputs.get("request.json"),StandardCharsets.UTF_8)));spaced.r.put("request_sha256",sha(spaced.inputs.get("request.json")));spaced.seal();record("noncanonical_original_request",false,spaced.check());
        F immutable=new F();VlmResultContract.Expected saved=immutable.expected();immutable.inputs.get("screen.png")[0]=0;immutable.owner.put("observation_id","later");
        record("immutable_expected_snapshot",true,VlmResultContract.verify(immutable.r,immutable.sidecars,saved,0));
        F opaque=new F();byte[] unchanged=b("原样保留，不翻译为动作。\n");raw(opaque,unchanged);opaque.seal();record("raw_text_not_parsed_or_authorized",true,opaque.check());
        if(!Arrays.equals(unchanged,b("原样保留，不翻译为动作。\n")))throw new AssertionError("raw rewritten");
        F ui=new F();boolean blocked=false;try{ui.expected(ui.owner,ui.taskOwner,WORKER_TICKS,NOW,GOOD,VlmResultContract.UI_VENUS_9B);}catch(IllegalArgumentException expected){blocked=true;}
        record("unverified_ui_venus_profile_refused",false,blocked?Arrays.asList("expected_constructor_refused"):new ArrayList<>());
        Map<String,Object> report=new LinkedHashMap<>();report.put("schema","hepta.vlm.result-contract.host-test.v1");report.put("all_pass",true);
        report.put("case_count",cases.size());report.put("cases",cases);report.put("required_receipt_fields",new ArrayList<>(VlmResultContract.requiredReceiptFields()));
        report.put("required_sidecars",new ArrayList<>(VlmResultContract.requiredSidecarNames()));report.put("required_original_inputs",new ArrayList<>(VlmResultContract.requiredOriginalInputNames()));
        report.put("real_template_sha256",sha(template));report.put("phone_operations",0);report.put("model_inference",false);report.put("android_runtime",false);
        report.put("actions_dispatched",false);report.put("business_completion_verified",false);Files.write(Paths.get(args[1]),json(report));
        System.out.println("PASS "+cases.size()+" host-only contract cases; zero phone/model/action operations");
    }
    static void raw(F f,byte[] b){f.sidecars.put("raw.txt",b);f.r.put("raw_bytes",(long)b.length);f.r.put("raw_sha256",sha(b));}
    static void rehashImage(F f)throws Exception{String h=sha(f.inputs.get("screen.png"));f.request.put("image_sha256",h);f.r.put("image_sha256",h);f.owner.put("image_sha256",h);f.owner();map(f.chunks.get(1)).put("image_sha256",h);f.chunks();}
    static void counts(F f,int text,int image,int pos){f.chunks.clear();f.chunks.add(text(0,text));f.chunks.add(image(1,image,pos,sha(f.inputs.get("screen.png"))));f.chunks();
        f.r.put("prompt_tokens",(long)text+image);f.r.put("prompt_positions",(long)text+pos);f.r.put("image_tokens",(long)image);f.r.put("prefill_positions",(long)text+pos);f.r.put("final_position",(long)text+pos+19);}
    static Map<String,Object> text(int i,int n){Map<String,Object> m=new LinkedHashMap<>();m.put("index",(long)i);m.put("type",0L);m.put("tokens",(long)n);m.put("positions",(long)n);m.put("token_ids_sha256_le32",sha(b("fixture-ids-"+i+"-"+n)));return m;}
    static Map<String,Object> image(int i,int n,int p,String hash){Map<String,Object> m=new LinkedHashMap<>();m.put("index",(long)i);m.put("type",1L);m.put("tokens",(long)n);m.put("positions",(long)p);m.put("image_sha256",hash);return m;}
    static byte[] formatted(Map<String,byte[]> inputs){return b("<|im_start|>system\n"+new String(inputs.get("system.txt"),StandardCharsets.UTF_8)+"<|im_end|>\n<|im_start|>user\n"+VlmResultContract.MEDIA_MARKER+new String(inputs.get("prompt.txt"),StandardCharsets.UTF_8)+"<|im_end|>\n<|im_start|>assistant\n");}
    static String identity(long ticks){return "hepta.worker-generation.v1\ntask_id="+T+"\nworker_generation="+G+"\nscope_token="+S+"\napp_uid="+UID+"\napp_pid="+APP+"\napp_start_ticks="+APP_TICKS+"\nleader_pid="+WORKER+"\nleader_start_ticks="+ticks+"\npgid="+WORKER+"\nboot_id="+BOOT+"\n";}
    static String input(String n){return n.equals("image")?"screen.png":n.equals("grammar")?"decision.gbnf":n.equals("owner")?"owner.json":n+".txt";}
    static byte[] b(String s){return s.getBytes(StandardCharsets.UTF_8);}static byte[] json(Object o){return b(VlmResultContract.canonicalJson(o)+"\n");}
    static String sha(byte[] b){return VlmResultContract.sha256(b);}static Map<String,Object> obj(byte[] b)throws Exception{return VlmResultContract.jsonObject(b);}
    @SuppressWarnings("unchecked")static Map<String,Object> map(Object o){return (Map<String,Object>)o;}
}
