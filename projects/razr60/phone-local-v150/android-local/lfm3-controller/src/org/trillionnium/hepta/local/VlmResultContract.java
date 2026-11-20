package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;

/**
 * Pure-Java verification of one native VLM result.
 *
 * This class neither interprets model text as an action nor authorizes dispatch.
 * Expected must be built from the caller's original immutable inputs, a fresh
 * trusted ownership projection, the held Process, and OwnedGenerationScope
 * evidence. Never derive Expected identity/lifecycle values from the result.
 * A successful return is an empty list. Every failed or incomplete proof returns
 * errors. The caller must still run its existing ActionDecision/DecisionGrammar
 * checks and recheck live ownership/cancellation immediately before dispatch.
 */
public final class VlmResultContract {
    private VlmResultContract() {}

    public static final int CONTEXT_TOKENS = 8192;
    public static final int IMAGE_MAX_TOKENS = 1024;
    public static final int OUTPUT_RESERVE_MARGIN = 16;
    public static final String MEDIA_MARKER = "<__media__>";
    private static final int MAX_RAW = 65536;
    private static final int MAX_RECEIPT = 262144;
    private static final int MAX_FORMATTED = 1048576;
    private static final int MAX_CHUNKS = 1048565;
    private static final long MAX_RUN_NS = 300000000000L;

    private static final Set<String> INPUT_NAMES = names(
            "request.json owner.json prompt.txt system.txt screen.png decision.gbnf worker-generation.identity");
    private static final Set<String> SIDECAR_NAMES = names(
            "native-result.json raw.txt gguf-chat-template.jinja formatted-prompt.txt chunks.json");
    private static final Set<String> REQUEST_KEYS = names(
            "schema profile request_id generation task_id owner_sha256 prompt_sha256 system_sha256 "
            + "image_sha256 grammar_sha256 max_tokens deadline_monotonic_ns image_width image_height");
    private static final Set<String> RECEIPT_KEYS = names(
            "schema request_id task_id generation scope_token profile request_sha256 owner_sha256 "
            + "image_sha256 grammar_sha256 prompt_sha256 system_sha256 generation_identity_sha256 "
            + "app_uid app_pid worker_pid expected_app_uid expected_parent_pid app_start_ticks boot_id "
            + "parent_death_signal parent_verified_before private_scope_verified_before "
            + "observed_parent_pid_before observed_parent_pid_after "
            + "model_filename model_bytes model_sha256 projector_filename projector_bytes projector_sha256 "
            + "model_files_full_sha_verified runtime_files_full_sha_verified "
            + "image_width image_height current_frame context_tokens max_output_tokens image_max_tokens "
            + "started_monotonic_ns deadline_monotonic_ns sampler grammar_root template_enable_thinking "
            + "native_tools_argument automatic_device_fallback zero_cpu_operations_proven "
            + "same_chunks_counted_and_evaluated context_shift_used input_image_transformed_by_worker "
            + "mtmd_internal_image_preprocessing actions_dispatched action_authorized business_completion_verified "
            + "generation_completed full_multimodal_admission_passed process_exit_observed cleanup_known "
            + "lm_device vision_device lm_device_description vision_device_description vision_max_allocation_bytes "
            + "architecture tokenizer_pre tokenizer_model chat_template_sha256 chat_template_bytes template_now_unix_ms "
            + "formatted_prompt_sha256 prompt_tokens prompt_positions image_tokens output_reserved_tokens "
            + "chunks_sha256 prefill_return_code prefill_positions generated_tokens_including_eog eog_observed "
            + "final_position parent_verified_after scope_unchanged_after native_return_code error cancel_signal "
            + "ended_monotonic_ns raw_sha256 raw_bytes");

    /** Profiles are local allowlisted constants, not caller/model supplied pins. */
    public static final class Profile {
        public final String id, modelFilename, modelSha256, projectorFilename, projectorSha256;
        public final String architecture, tokenizerPre, tokenizerModel, templateSha256;
        public final long modelBytes, projectorBytes;
        private Profile(String id, String mf, long mb, String ms, String pf, long pb, String ps,
                        String arch, String pre, String tokenizer, String template) {
            this.id=id; modelFilename=mf; modelBytes=mb; modelSha256=ms;
            projectorFilename=pf; projectorBytes=pb; projectorSha256=ps;
            architecture=arch; tokenizerPre=pre; tokenizerModel=tokenizer; templateSha256=template;
        }
    }

    public static final Profile GUI_OWL_4B = new Profile(
            "gui-owl-1.5-4b-instruct-i1-q4_0",
            "GUI-Owl-1.5-4B-Instruct.i1-Q4_0.gguf", 2375774624L,
            "c71f372d2e2b71f173622f1966ac6a1bc60da1c2dbdd6d92534ab6f83724b8df",
            "GUI-Owl-1.5-4B-Instruct.mmproj-f16.gguf", 836180288L,
            "eabdc0291d460f2e68874f51044030a7da8fe956c2a6b86abd69fd701227c105",
            "qwen3vl", "qwen2", "gpt2",
            "3636d0f0bd6bef02654cdffdc447b79cb2cef8ab02cc75267345946291a489e4");

    /** Official LFM3-VL QAD Q4_0 plus F16 projector, observation-only in LocalRuntimeConfig. */
    public static final Profile LFM3_VL_2B = new Profile(
            "lfm3-vl-2b-qad-q4_0",
            "LFM3-VL-2B-QAD-Q4_0.gguf", 1049615648L,
            "621c455376cb96a20891697deb9975c6fb47dd5ea98ed3ad1f3b7e8f24f0b1e6",
            "mmproj-LFM3-VL-2B-F16.gguf", 378996032L,
            "1d8e6e58eefc093e09d6332f081516e1ddbd5b35cfca7f35463fb270db230b1e",
            "lfm3", "lfm2", "gpt2",
            "f45005c50cd2a97329722bf3a2dee9f16c04cdf825a589b280fb7e99e6827818");

    public static final Profile UI_VENUS_9B = new Profile(
            "ui-venus-2-9b-q4_0",
            "UI-Venus-2-9B-Q4_0.gguf", 5482832672L,
            "2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb",
            "mmproj-UI-Venus-2-9B-f16.gguf", 918165664L,
            "6ef77c3bf87391664be7cd71c595352e7281dabe52f24e961e2deace550f3af2",
            "qwen35", "qwen35", null,
            "4a3d47f53cc133e5dc859e9532fcb74baf0459ef426b8f107a3ac6e5926533e5");

    /** Closed names select complete local pins, never caller-supplied metadata. */
    public static Profile named(String id){
        if(GUI_OWL_4B.id.equals(id))return GUI_OWL_4B;
        if(LFM3_VL_2B.id.equals(id))return LFM3_VL_2B;
        throw new IllegalArgumentException("visual artifact profile is not admitted");
    }

    /** Independently observed by Java; native result flags cannot fill these. */
    public static final class Lifecycle {
        public final boolean directExitObserved, cleanupKnown, cleanupUnforced;
        public final boolean parentStillMatches, scopeStillCurrent, cancelled;
        public Lifecycle(boolean directExitObserved, boolean cleanupKnown, boolean cleanupUnforced,
                         boolean parentStillMatches, boolean scopeStillCurrent, boolean cancelled) {
            this.directExitObserved=directExitObserved; this.cleanupKnown=cleanupKnown;
            this.cleanupUnforced=cleanupUnforced; this.parentStillMatches=parentStillMatches;
            this.scopeStillCurrent=scopeStillCurrent; this.cancelled=cancelled;
        }
    }

    public static final class Expected {
        public final String taskId, generation, requestId, scopeToken, bootId;
        public final int appUid, appPid, workerPid;
        public final long appStartTicks, workerStartTicks, acceptanceMonotonicNs;
        public final Profile profile;
        public final Lifecycle lifecycle;
        public final Map<String,Object> currentFrame;
        private final Map<String,byte[]> inputs;
        private final byte[] taskOwnerEvidence;

        public Expected(String taskId, String generation, String requestId, String scopeToken,
                        int appUid, int appPid, int workerPid, long appStartTicks, long workerStartTicks,
                        String bootId, Profile profile, Map<String,byte[]> originalInputs,
                        Map<String,Object> currentFrame, byte[] taskOwnerEvidence,
                        long acceptanceMonotonicNs, Lifecycle lifecycle) {
            if (!id(taskId)||!id(generation)||!id(requestId)||!id(scopeToken)
                    ||appUid<10000||appPid<=1||workerPid<=1||workerPid==appPid
                    ||appStartTicks<=0||workerStartTicks<=0||acceptanceMonotonicNs<=0
                    ||bootId==null||!bootId.matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                    // UI-Venus stays unavailable until its tokenizer metadata is
                    // independently read from the pinned file. Do not infer it.
                    ||(profile!=GUI_OWL_4B&&profile!=LFM3_VL_2B)||lifecycle==null)
                throw new IllegalArgumentException("invalid independent VLM expectation");
            this.taskId=taskId; this.generation=generation; this.requestId=requestId;
            this.scopeToken=scopeToken; this.appUid=appUid; this.appPid=appPid;
            this.workerPid=workerPid; this.appStartTicks=appStartTicks; this.workerStartTicks=workerStartTicks;
            this.bootId=bootId; this.profile=profile; this.acceptanceMonotonicNs=acceptanceMonotonicNs;
            this.lifecycle=lifecycle; this.inputs=copyBytes(originalInputs);
            this.currentFrame=freezeObject(currentFrame);
            this.taskOwnerEvidence=taskOwnerEvidence==null?null:taskOwnerEvidence.clone();
        }
        public byte[] originalInput(String name) {
            byte[] b=inputs.get(name); return b==null?null:b.clone();
        }
    }

    public static Set<String> requiredReceiptFields() { return RECEIPT_KEYS; }
    public static Set<String> requiredSidecarNames() { return SIDECAR_NAMES; }
    public static Set<String> requiredOriginalInputNames() { return INPUT_NAMES; }

    public static List<String> verify(Map<String,Object> receipt, Map<String,byte[]> sidecars,
                                      Expected expected, int actualExit) {
        List<String> errors=new ArrayList<>();
        if (expected==null) { errors.add("expected_missing"); return Collections.unmodifiableList(errors); }
        try {
            verifyInternal(errors,receipt,copyBytes(sidecars),expected,actualExit);
        } catch (Exception failure) {
            // No model text, screen text or private file contents are exposed in errors.
            errors.add("contract_input_unreadable:"+failure.getClass().getSimpleName());
        }
        return Collections.unmodifiableList(errors);
    }

    private static void verifyInternal(List<String> e, Map<String,Object> supplied,
                                       Map<String,byte[]> sidecars, Expected x, int actualExit) throws Exception {
        check(e,actualExit==0,"actual_process_exit");
        check(e,x.lifecycle.directExitObserved,"direct_process_exit_not_observed");
        check(e,x.lifecycle.cleanupKnown&&x.lifecycle.cleanupUnforced,"owned_generation_cleanup_not_unforced");
        check(e,x.lifecycle.parentStillMatches,"live_parent_identity_mismatch");
        check(e,x.lifecycle.scopeStillCurrent,"live_scope_ownership_mismatch");
        check(e,!x.lifecycle.cancelled,"cancelled");
        check(e,x.inputs.keySet().equals(INPUT_NAMES),"original_input_membership");
        check(e,sidecars.keySet().equals(SIDECAR_NAMES),"sidecar_membership");

        byte[] request=bytes(e,x.inputs,"request.json",1,16384);
        byte[] owner=bytes(e,x.inputs,"owner.json",1,131072);
        byte[] prompt=bytes(e,x.inputs,"prompt.txt",1,131072);
        byte[] system=bytes(e,x.inputs,"system.txt",1,65536);
        byte[] image=bytes(e,x.inputs,"screen.png",33,32*1024*1024);
        byte[] grammar=bytes(e,x.inputs,"decision.gbnf",1,262144);
        byte[] identity=bytes(e,x.inputs,"worker-generation.identity",1,2047);
        byte[] receiptBytes=bytes(e,sidecars,"native-result.json",1,MAX_RECEIPT);
        byte[] raw=bytes(e,sidecars,"raw.txt",1,MAX_RAW);
        byte[] template=bytes(e,sidecars,"gguf-chat-template.jinja",1,65536);
        byte[] formatted=bytes(e,sidecars,"formatted-prompt.txt",1,MAX_FORMATTED);
        byte[] chunksBytes=bytes(e,sidecars,"chunks.json",1,MAX_CHUNKS);
        if (request==null||owner==null||prompt==null||system==null||image==null||grammar==null
                ||identity==null||receiptBytes==null||raw==null||template==null||formatted==null||chunksBytes==null)
            return;

        Map<String,Object> r=parseObject(e,receiptBytes,"native_result_json");
        Map<String,Object> q=parseObject(e,request,"request_json");
        Map<String,Object> frame=parseObject(e,owner,"owner_json");
        if (r==null||q==null||frame==null) return;
        check(e,deepEqual(r,supplied),"supplied_receipt_not_identical_to_sidecar");
        check(e,r.keySet().equals(RECEIPT_KEYS),"result_field_membership");
        check(e,q.keySet().equals(REQUEST_KEYS),"request_field_membership");
        String canonical=canonicalJson(q);
        String requestText=utf8(e,request,"request_utf8");
        check(e,canonical.equals(requestText)||(canonical+"\n").equals(requestText),"request_not_canonical");

        equal(e,q,"schema","hepta.vlm.request.v1");
        equal(e,r,"schema","hepta.vlm.result.v1");
        for(Map<String,Object> object:Arrays.asList(q,r,frame)) {
            equal(e,object,"task_id",x.taskId);
            equal(e,object,"generation",x.generation);
            equal(e,object,"request_id",x.requestId);
        }
        equal(e,q,"profile",x.profile.id);
        equal(e,r,"profile",x.profile.id);
        equal(e,r,"scope_token",x.scopeToken);
        equal(e,frame,"scope_token",x.scopeToken);
        equal(e,frame,"schema","hepta.vlm.current-frame.v1");
        check(e,deepEqual(frame,x.currentFrame),"original_owner_not_current_frame");
        check(e,deepEqual(frame,r.get("current_frame")),"receipt_current_frame_mismatch");
        check(e,x.taskOwnerEvidence!=null&&x.taskOwnerEvidence.length>0,"task_owner_original_bytes_missing");
        if(x.taskOwnerEvidence!=null) equal(e,frame,"task_owner_sha256",sha256(x.taskOwnerEvidence));

        bind(e,r,"request_sha256",request);
        bind(e,r,"generation_identity_sha256",identity);
        String[] hashes={"owner_sha256","prompt_sha256","system_sha256","image_sha256","grammar_sha256"};
        byte[][] contents={owner,prompt,system,image,grammar};
        for(int i=0;i<hashes.length;i++){bind(e,q,hashes[i],contents[i]);bind(e,r,hashes[i],contents[i]);}
        bind(e,frame,"image_sha256",image); bind(e,frame,"grammar_sha256",grammar);

        long maximum=integer(q.get("max_tokens")), width=integer(q.get("image_width")),
                height=integer(q.get("image_height")), deadline=integer(q.get("deadline_monotonic_ns"));
        check(e,maximum>=1&&maximum<=256,"original_max_tokens");
        check(e,width>=1&&width<=8192&&height>=1&&height<=8192&&width*height<=24000000L,"original_image_dimensions");
        check(e,deadline>0,"original_deadline");
        for(Map<String,Object> object:Arrays.asList(r,frame)){
            number(e,object,"image_width",width); number(e,object,"image_height",height);
        }
        verifyPng(e,image,width,height);
        boundedString(e,frame,"observation_id",128);
        boundedString(e,frame,"background_generation",128);
        boundedString(e,frame,"package_name",256);
        check(e,range(frame.get("display_id"),1,Integer.MAX_VALUE),"current_frame_display");
        check(e,range(frame.get("window_id"),0,Integer.MAX_VALUE),"current_frame_window");
        check(e,range(frame.get("rotation"),0,3),"current_frame_rotation");
        check(e,range(frame.get("captured_elapsed_ms"),1,Long.MAX_VALUE),"original_capture_time");
        // captured_elapsed_ms and System.nanoTime are different clocks. Freshness
        // is supplied by the independently refreshed ownership/lifecycle proof.

        number(e,r,"app_uid",x.appUid); number(e,r,"expected_app_uid",x.appUid);
        number(e,r,"app_pid",x.appPid); number(e,r,"expected_parent_pid",x.appPid);
        number(e,r,"observed_parent_pid_before",x.appPid); number(e,r,"observed_parent_pid_after",x.appPid);
        number(e,r,"worker_pid",x.workerPid); number(e,r,"app_start_ticks",x.appStartTicks);
        equal(e,r,"boot_id",x.bootId); number(e,r,"parent_death_signal",9);
        verifyGenerationIdentity(e,identity,x);
        for(String key:new String[]{"parent_verified_before","parent_verified_after",
                "private_scope_verified_before","scope_unchanged_after"}) equal(e,r,key,Boolean.TRUE);

        Profile p=x.profile;
        equal(e,r,"model_filename",p.modelFilename); number(e,r,"model_bytes",p.modelBytes);
        equal(e,r,"model_sha256",p.modelSha256);
        equal(e,r,"projector_filename",p.projectorFilename); number(e,r,"projector_bytes",p.projectorBytes);
        equal(e,r,"projector_sha256",p.projectorSha256);
        equal(e,r,"model_files_full_sha_verified",Boolean.TRUE);
        equal(e,r,"runtime_files_full_sha_verified",Boolean.TRUE);
        equal(e,r,"architecture",p.architecture); equal(e,r,"tokenizer_pre",p.tokenizerPre);
        equal(e,r,"tokenizer_model",p.tokenizerModel);
        equal(e,r,"chat_template_sha256",p.templateSha256);
        check(e,p.templateSha256.equals(sha256(template)),"template_not_profile_pin");
        number(e,r,"chat_template_bytes",template.length);
        check(e,range(r.get("template_now_unix_ms"),1,Long.MAX_VALUE),"template_time");
        utf8(e,template,"template_utf8");
        String promptText=utf8(e,prompt,"original_prompt_utf8"),systemText=utf8(e,system,"original_system_utf8");
        String grammarText=utf8(e,grammar,"original_grammar_utf8"),formattedText=utf8(e,formatted,"formatted_prompt_utf8");
        utf8(e,raw,"raw_utf8");
        check(e,promptText!=null&&promptText.indexOf('\0')<0&&systemText!=null&&systemText.indexOf('\0')<0,
                "original_text_contains_nul");
        check(e,grammarText!=null&&grammarText.indexOf('\0')<0,"grammar_contains_nul");
        check(e,promptText!=null&&!promptText.contains(MEDIA_MARKER)
                &&systemText!=null&&!systemText.contains(MEDIA_MARKER),"original_reserved_media_marker");
        bind(e,r,"formatted_prompt_sha256",formatted);
        check(e,formattedText!=null&&occurrences(formattedText,MEDIA_MARKER)==1,"formatted_image_marker_count");
        check(e,formattedText!=null&&promptText!=null&&formattedText.contains(promptText),"formatted_original_prompt_missing");
        check(e,formattedText!=null&&systemText!=null&&formattedText.contains(systemText),"formatted_original_system_missing");
        // This exact pinned GUI-Owl template has no date branch, uses strings
        // unchanged when tools are absent, and adds this assistant prefix.
        // Validate bytes; never replace the native formatted prompt or raw text.
        if (p==GUI_OWL_4B&&promptText!=null&&systemText!=null) {
            String expectedFormatted="<|im_start|>system\n"+systemText+"<|im_end|>\n"
                    +"<|im_start|>user\n"+MEDIA_MARKER+promptText+"<|im_end|>\n"
                    +"<|im_start|>assistant\n";
            check(e,Arrays.equals(formatted,expectedFormatted.getBytes(StandardCharsets.UTF_8)),
                    "formatted_prompt_not_exact_pinned_template");
        }
        if (p==LFM3_VL_2B&&promptText!=null&&systemText!=null) {
            // Exact embedded template. add_bos=false means its explicit BOS stays
            // in common_chat_templates_apply's output. The worker disables thinking.
            String expectedFormatted="<|startoftext|>"
                    +(systemText.isEmpty()?"":"<|im_start|>system\n"+systemText+"<|im_end|>\n")
                    +"<|im_start|>user\n"+MEDIA_MARKER+promptText+"<|im_end|>\n"
                    +"<|im_start|>assistant\n<think></think>";
            check(e,Arrays.equals(formatted,expectedFormatted.getBytes(StandardCharsets.UTF_8)),
                    "formatted_prompt_not_exact_pinned_template");
        }
        bind(e,r,"chunks_sha256",chunksBytes);
        bind(e,r,"raw_sha256",raw); number(e,r,"raw_bytes",raw.length);

        equal(e,r,"lm_device","HTP0"); equal(e,r,"vision_device","GPUOpenCL");
        boundedString(e,r,"lm_device_description",4096); boundedString(e,r,"vision_device_description",4096);
        check(e,range(r.get("vision_max_allocation_bytes"),1,Long.MAX_VALUE),"vision_allocation_limit");
        number(e,r,"context_tokens",CONTEXT_TOKENS); number(e,r,"max_output_tokens",maximum);
        number(e,r,"output_reserved_tokens",maximum); number(e,r,"image_max_tokens",IMAGE_MAX_TOKENS);
        equal(e,r,"sampler","current-frame-gbnf-then-greedy"); equal(e,r,"grammar_root","root");
        for(String key:new String[]{"generation_completed","eog_observed","full_multimodal_admission_passed",
                "same_chunks_counted_and_evaluated","mtmd_internal_image_preprocessing"}) equal(e,r,key,Boolean.TRUE);
        for(String key:new String[]{"template_enable_thinking","native_tools_argument","automatic_device_fallback",
                "zero_cpu_operations_proven","context_shift_used","input_image_transformed_by_worker",
                "actions_dispatched","action_authorized","business_completion_verified",
                "process_exit_observed","cleanup_known"}) equal(e,r,key,Boolean.FALSE);
        number(e,r,"native_return_code",0); number(e,r,"cancel_signal",0);
        equal(e,r,"error","none"); number(e,r,"prefill_return_code",0);

        verifyChunks(e,r,chunksBytes,sha256(image),maximum);
        long generated=integer(r.get("generated_tokens_including_eog"));
        check(e,generated>=2&&generated<=maximum,"generated_token_count");
        long positions=integer(r.get("prompt_positions"));
        number(e,r,"prefill_positions",positions);
        if(positions>0&&positions<=CONTEXT_TOKENS&&generated>=2&&generated<=256)
            number(e,r,"final_position",positions+generated-1);
        else check(e,false,"final_position_unverifiable");
        check(e,range(r.get("final_position"),1,CONTEXT_TOKENS),"final_position_capacity");

        long started=integer(r.get("started_monotonic_ns")),ended=integer(r.get("ended_monotonic_ns"));
        number(e,r,"deadline_monotonic_ns",deadline);
        check(e,started>0&&deadline>started&&deadline-started<=MAX_RUN_NS,"native_original_deadline_window");
        check(e,ended>=started&&ended>0&&ended<deadline,"native_finished_before_deadline");
        check(e,x.acceptanceMonotonicNs>=ended&&x.acceptanceMonotonicNs<deadline,"acceptance_before_original_deadline");
    }

    private static void verifyChunks(List<String> e,Map<String,Object> r,byte[] bytes,String imageSha,long maximum) {
        List<?> chunks;
        try {
            ByteArrayOutputStream wrapped=new ByteArrayOutputStream(bytes.length+11);
            wrapped.write("{\"value\":".getBytes(StandardCharsets.UTF_8));
            wrapped.write(bytes); wrapped.write('}');
            Object value=MobiMindContract.jsonObject(wrapped.toByteArray()).get("value");
            if(!(value instanceof List)){check(e,false,"chunks_not_array");return;}
            chunks=(List<?>)value;
        } catch(Exception failure){check(e,false,"chunks_json");return;}
        check(e,!chunks.isEmpty()&&chunks.size()<=16384,"chunk_count");
        if(chunks.size()>16384)return;
        long totalTokens=0,totalPositions=0,imageTokens=0,textTokens=0;
        int imageChunks=0,textChunks=0;
        for(int i=0;i<chunks.size();i++){
            Map<String,Object> c=object(chunks.get(i));
            if(c==null){check(e,false,"chunk_object:"+i);continue;}
            long kind=integer(c.get("type")),tokens=integer(c.get("tokens")),positions=integer(c.get("positions"));
            number(e,c,"index",i);
            check(e,tokens>=0&&tokens<=CONTEXT_TOKENS,"chunk_tokens:"+i);
            check(e,positions>=0&&positions<=CONTEXT_TOKENS,"chunk_positions:"+i);
            if(tokens<0||tokens>CONTEXT_TOKENS||positions<0||positions>CONTEXT_TOKENS)continue;
            if(kind==0){
                check(e,c.keySet().equals(names("index type tokens positions token_ids_sha256_le32")),"text_chunk_fields:"+i);
                hashString(e,c.get("token_ids_sha256_le32"),"text_token_ids_sha256:"+i);
                check(e,tokens==positions,"text_position_count:"+i);
                textChunks++;textTokens+=tokens;
            } else if(kind==1){
                check(e,c.keySet().equals(names("index type tokens positions image_sha256")),"image_chunk_fields:"+i);
                equal(e,c,"image_sha256",imageSha);
                check(e,tokens>0&&positions>0,"image_chunk_empty:"+i);
                imageChunks++;imageTokens+=tokens;
            } else {
                check(e,false,"non_image_media_chunk:"+i);
            }
            totalTokens+=tokens; totalPositions+=positions;
        }
        check(e,imageChunks>0&&textChunks>0&&textTokens>0,"full_text_and_image_input");
        check(e,imageTokens>0&&imageTokens<=IMAGE_MAX_TOKENS,"image_token_budget");
        check(e,totalTokens>0&&totalTokens<=CONTEXT_TOKENS,"input_token_sum");
        check(e,totalPositions>0&&totalPositions<=CONTEXT_TOKENS,"input_position_sum");
        check(e,totalTokens==textTokens+imageTokens,"input_kind_sum");
        number(e,r,"prompt_tokens",totalTokens); number(e,r,"prompt_positions",totalPositions);
        number(e,r,"image_tokens",imageTokens); number(e,r,"prefill_positions",totalPositions);
        check(e,maximum>=1&&maximum<=256
                &&totalTokens<=CONTEXT_TOKENS-maximum-OUTPUT_RESERVE_MARGIN
                &&totalPositions<=CONTEXT_TOKENS-maximum-OUTPUT_RESERVE_MARGIN,"full_multimodal_context_budget");
    }

    private static void verifyGenerationIdentity(List<String> e,byte[] bytes,Expected x) {
        String expected="hepta.worker-generation.v1\n"
                +"task_id="+x.taskId+"\nworker_generation="+x.generation+"\nscope_token="+x.scopeToken
                +"\napp_uid="+x.appUid+"\napp_pid="+x.appPid+"\napp_start_ticks="+x.appStartTicks
                +"\nleader_pid="+x.workerPid+"\nleader_start_ticks="+x.workerStartTicks
                +"\npgid="+x.workerPid+"\nboot_id="+x.bootId+"\n";
        check(e,Arrays.equals(bytes,expected.getBytes(StandardCharsets.UTF_8)),"original_generation_identity");
    }

    private static void verifyPng(List<String> e,byte[] image,long width,long height) {
        byte[] magic={(byte)137,80,78,71,13,10,26,10};
        boolean header=image.length>=33&&Arrays.equals(magic,Arrays.copyOf(image,8))
                &&be32(image,8)==13&&image[12]=='I'&&image[13]=='H'&&image[14]=='D'&&image[15]=='R';
        check(e,header,"original_png_header");
        if(!header)return;
        check(e,be32(image,16)==width&&be32(image,20)==height,"original_png_dimensions");
        CRC32 crc=new CRC32();crc.update(image,12,17);
        check(e,crc.getValue()==be32(image,29),"original_png_ihdr_crc");
    }

    private static long be32(byte[] b,int at) {
        return ((long)(b[at]&255)<<24)|((long)(b[at+1]&255)<<16)|((long)(b[at+2]&255)<<8)|(b[at+3]&255);
    }
    private static int occurrences(String s,String needle) {
        int count=0,at=0;while((at=s.indexOf(needle,at))>=0){count++;at+=needle.length();}return count;
    }
    private static byte[] bytes(List<String> e,Map<String,byte[]> files,String name,int min,int max) {
        byte[] b=files.get(name);
        if(b==null||b.length<min||b.length>max){check(e,false,"file_size:"+name);return null;}
        return b;
    }
    private static Map<String,Object> parseObject(List<String> e,byte[] bytes,String label) {
        try{return MobiMindContract.jsonObject(bytes);}
        catch(Exception failure){check(e,false,label);return null;}
    }
    private static String utf8(List<String> e,byte[] bytes,String label) {
        try{return MobiMindContract.utf8(bytes);}
        catch(Exception failure){check(e,false,label);return null;}
    }
    private static void boundedString(List<String> e,Map<String,Object> m,String key,int max) {
        Object v=m.get(key);
        check(e,v instanceof String&&!((String)v).isEmpty()&&((String)v).indexOf('\0')<0
                &&((String)v).getBytes(StandardCharsets.UTF_8).length<=max,key);
    }
    private static void bind(List<String> e,Map<String,Object> m,String key,byte[] bytes) {
        equal(e,m,key,sha256(bytes));
    }
    private static void hashString(List<String> e,Object v,String label) {
        check(e,v instanceof String&&((String)v).matches("[0-9a-f]{64}"),label);
    }
    private static boolean id(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    private static boolean range(Object v,long min,long max){long n=integer(v);return n>=min&&n<=max;}
    private static long integer(Object v) {
        return v instanceof Long||v instanceof Integer?((Number)v).longValue():Long.MIN_VALUE;
    }
    private static void number(List<String> e,Map<String,Object> m,String key,long expected) {
        check(e,integer(m.get(key))==expected,key);
    }
    private static void equal(List<String> e,Map<String,Object> m,String key,Object expected) {
        check(e,expected!=null&&expected.equals(m.get(key)),key);
    }
    private static void check(List<String> e,boolean ok,String label){if(!ok&&e.size()<256)e.add(label);}
    private static Set<String> names(String s) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(s.split(" "))));
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> object(Object v) {
        if(!(v instanceof Map))return null;
        for(Object key:((Map<?,?>)v).keySet())if(!(key instanceof String))return null;
        return (Map<String,Object>)v;
    }
    private static Map<String,byte[]> copyBytes(Map<String,byte[]> source) {
        Map<String,byte[]> copy=new LinkedHashMap<>();
        if(source!=null&&source.size()>32)throw new IllegalArgumentException("file membership bound");
        long total=0;
        if(source!=null)for(Map.Entry<String,byte[]> entry:source.entrySet()){
            if(entry.getKey()==null)throw new IllegalArgumentException("null file name");
            byte[] value=entry.getValue();
            if(value!=null){
                total+=value.length;
                if(value.length>32*1024*1024||total>40*1024*1024)
                    throw new IllegalArgumentException("file snapshot bound");
            }
            copy.put(entry.getKey(),entry.getValue()==null?null:entry.getValue().clone());
        }
        return Collections.unmodifiableMap(copy);
    }
    private static Map<String,Object> freezeObject(Map<String,Object> source) {
        if(source==null)return Collections.emptyMap();
        @SuppressWarnings("unchecked") Map<String,Object> result=(Map<String,Object>)freeze(source,0);
        return result;
    }
    private static Object freeze(Object v,int depth) {
        if(depth>32)throw new IllegalArgumentException("expected projection nesting");
        if(v==null||v instanceof String||v instanceof Boolean||v instanceof Integer||v instanceof Long||v instanceof Double)return v;
        if(v instanceof Map){
            Map<String,Object> copy=new LinkedHashMap<>();
            if(((Map<?,?>)v).size()>65536)throw new IllegalArgumentException("expected projection members");
            for(Map.Entry<?,?> entry:((Map<?,?>)v).entrySet()){
                if(!(entry.getKey() instanceof String))throw new IllegalArgumentException("expected projection key");
                copy.put((String)entry.getKey(),freeze(entry.getValue(),depth+1));
            }
            return Collections.unmodifiableMap(copy);
        }
        if(v instanceof List){
            List<Object> copy=new ArrayList<>();
            if(((List<?>)v).size()>65536)throw new IllegalArgumentException("expected projection values");
            for(Object item:(List<?>)v)copy.add(freeze(item,depth+1));
            return Collections.unmodifiableList(copy);
        }
        throw new IllegalArgumentException("non-JSON expected projection");
    }
    private static boolean deepEqual(Object a,Object b) {
        return deepEqual(a,b,0);
    }
    private static boolean deepEqual(Object a,Object b,int depth) {
        if(depth>32)return false;
        if(a==null||b==null)return a==b;
        if((a instanceof Integer||a instanceof Long)&&(b instanceof Integer||b instanceof Long))
            return ((Number)a).longValue()==((Number)b).longValue();
        if(a instanceof Map&&b instanceof Map){
            Map<?,?> am=(Map<?,?>)a,bm=(Map<?,?>)b;
            if(!am.keySet().equals(bm.keySet()))return false;
            for(Object key:am.keySet())if(!deepEqual(am.get(key),bm.get(key),depth+1))return false;
            return true;
        }
        if(a instanceof List&&b instanceof List){
            List<?> al=(List<?>)a,bl=(List<?>)b;
            if(al.size()!=bl.size())return false;
            for(int i=0;i<al.size();i++)if(!deepEqual(al.get(i),bl.get(i),depth+1))return false;
            return true;
        }
        return a.getClass()==b.getClass()&&a.equals(b);
    }

    public static String sha256(byte[] bytes){return MobiMindContract.sha(bytes);}
    public static Map<String,Object> jsonObject(byte[] bytes)throws Exception{return MobiMindContract.jsonObject(bytes);}

    /** Compact JSON for request/receipt fixtures; raw model output never enters this function. */
    public static String canonicalJson(Object value) {
        StringBuilder out=new StringBuilder();appendJson(out,value,0);return out.toString();
    }
    private static void appendJson(StringBuilder out,Object value,int depth) {
        if(depth>32)throw new IllegalArgumentException("JSON nesting");
        if(value==null){out.append("null");return;}
        if(value instanceof String){appendString(out,(String)value);return;}
        if(value instanceof Boolean||value instanceof Integer||value instanceof Long){out.append(value);return;}
        if(value instanceof Double){
            double n=(Double)value;if(Double.isNaN(n)||Double.isInfinite(n))throw new IllegalArgumentException("nonfinite JSON");
            out.append(value);return;
        }
        if(value instanceof Map){
            out.append('{');boolean first=true;
            for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()){
                if(!(entry.getKey() instanceof String))throw new IllegalArgumentException("JSON object key");
                if(!first)out.append(',');first=false;appendString(out,(String)entry.getKey());out.append(':');
                appendJson(out,entry.getValue(),depth+1);
            }out.append('}');return;
        }
        if(value instanceof List){
            out.append('[');boolean first=true;for(Object item:(List<?>)value){
                if(!first)out.append(',');first=false;appendJson(out,item,depth+1);
            }out.append(']');return;
        }
        throw new IllegalArgumentException("non-JSON value");
    }
    private static void appendString(StringBuilder out,String text) {
        out.append('"');
        for(int i=0;i<text.length();i++){
            char c=text.charAt(i);
            switch(c){
                case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;
                case '\b':out.append("\\b");break;case '\f':out.append("\\f");break;
                case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;
                default:
                    if(c<32)out.append(String.format(java.util.Locale.ROOT,"\\u%04x",(int)c));
                    else if(Character.isHighSurrogate(c)){
                        if(i+1>=text.length()||!Character.isLowSurrogate(text.charAt(i+1)))throw new IllegalArgumentException("unpaired surrogate");
                        out.append(c).append(text.charAt(++i));
                    }else if(Character.isLowSurrogate(c))throw new IllegalArgumentException("unpaired surrogate");
                    else out.append(c);
            }
        }out.append('"');
    }
}

