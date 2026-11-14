package org.trillionnium.hepta.local;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.json.JSONObject;

/** Immutable audit proof for one failed SDK call. It cannot qualify generation or an action. */
final class SdkExceptionFailure {
    private static final String SDK_COMMIT="071f609995470bdb0e0769ab964754adfaab7e47";
    static final class Expected {
        final LocalRuntimeConfig config;
        final String generation,taskId,requestId,modelPath,runPath,promptHash,systemHash,grammarHash;
        final long pid;
        final int sequence,accepted,maxTokens;
        Expected(LocalRuntimeConfig config,String generation,String taskId,String requestId,long pid,
                int sequence,int accepted,int maxTokens,String modelPath,String runPath,
                byte[] prompt,byte[] system,byte[] grammar)throws Exception{
            this.config=config;this.generation=generation;this.taskId=taskId;this.requestId=requestId;
            this.pid=pid;this.sequence=sequence;this.accepted=accepted;this.maxTokens=maxTokens;
            this.modelPath=modelPath;this.runPath=runPath;
            promptHash=hash(prompt);systemHash=system==null?null:hash(system);grammarHash=grammar==null?null:hash(grammar);
            need(config!=null&&config.profile.exactTokenizationRequired&&validId(generation)&&validId(taskId)
                    &&validId(requestId)&&pid>0&&sequence>=1&&sequence<=64&&accepted==sequence-1
                    &&maxTokens>=1&&maxTokens<=1024&&modelPath!=null&&modelPath.startsWith("/")
                    &&runPath!=null&&runPath.startsWith("/")&&runPath.endsWith("/"+requestId),"expected request identity");
        }
    }
    final String generation,taskId,requestId,requestHash,sessionHash,promptEvidenceHash,formattedHash,inputIdsHash,rawHash,kind;
    final long pid;
    final int sequence,accepted;
    private final LocalRuntimeConfig config;
    private SdkExceptionFailure(Expected e,String requestHash,String sessionHash,String evidenceHash,
            String formattedHash,String idsHash,String rawHash,String kind){
        generation=e.generation;taskId=e.taskId;requestId=e.requestId;pid=e.pid;sequence=e.sequence;accepted=e.accepted;
        config=e.config;this.requestHash=requestHash;this.sessionHash=sessionHash;promptEvidenceHash=evidenceHash;
        this.formattedHash=formattedHash;inputIdsHash=idsHash;this.rawHash=rawHash;this.kind=kind;
    }
    static SdkExceptionFailure bind(Expected e,byte[] requestBytes,byte[] sessionBytes,byte[] evidenceBytes,
            byte[] formatted,byte[] ids,byte[] raw,boolean rawPresent,boolean observed,Integer exit,boolean force)throws Exception{
        need(e!=null&&observed&&exit!=null&&exit.intValue()==70&&!force,"actual non-forced wait70 required");
        JSONObject r=json(requestBytes),s=json(sessionBytes),p=json(evidenceBytes);
        need("hepta.geniex-task-request.result.v1".equals(r.opt("schema"))
                &&e.generation.equals(r.opt("worker_generation"))&&e.taskId.equals(r.opt("task_id"))
                &&e.requestId.equals(r.opt("request_id")),"native request identity");
        numbers(r,new String[]{"pid","request_sequence","request_status","model_hash_count","model_create_count","sdk_init_count",
                "model_reset_count","model_reset_rc","signal_observed","first_signal_phase","generate_attempt_count"},
                new long[]{e.pid,e.sequence,70,1,1,1,e.sequence,0,0,0,1});
        truths(r,"worker_retained","model_metadata_unchanged","input_metadata_unchanged");
        falses(r,"production_receipt","native_action_authorized","process_exit_observed","generation_complete",
                "automatic_retry","automatic_cpu_fallback","chat_template_enable_thinking","deadline_observed","callback_limit_observed");
        need("sdk_cpp_exception".equals(r.opt("error"))&&"sdk_exception".equals(r.opt("worker_outcome"))
                &&"task_generation".equals(r.opt("model_hash_scope"))
                &&r.opt("model_hash_performed_this_request")==Boolean.valueOf(e.sequence==1),"specific SDK exception");
        nullValue(r,"worker_exit_status_planned");nullValue(r,"device_warning");nullValue(r,"vit_device_requested");
        need(LocalRuntimeConfig.SDK_VERSION.equals(r.opt("sdk_version"))&&SDK_COMMIT.equals(r.opt("sdk_source_commit"))
                &&LocalRuntimeConfig.MODE.equals(r.opt("mode"))&&LocalRuntimeConfig.RUNTIME.equals(r.opt("runtime"))
                &&e.config.compute.equals(r.opt("compute_requested"))&&e.config.expectedDevice().equals(r.opt("device_resolved"))
                &&e.config.profile.id.equals(r.opt("model_profile"))&&e.config.profile.architecture.equals(r.opt("model_architecture"))
                &&e.config.profile.sha256.equals(r.opt("model_sha256_verified"))&&e.modelPath.equals(r.opt("model_path")),"model/runtime contract");
        numbers(r,new String[]{"model_bytes_verified","n_ctx_create","max_tokens","power_mode_create"},
                new long[]{e.config.profile.bytes,e.config.contextTokens,e.maxTokens,6});
        long layers=number(r,"n_gpu_layers_create");
        need(layers>=Integer.MIN_VALUE&&layers<=Integer.MAX_VALUE
                &&e.config.matchesResolvedDevice(r.optString("device_resolved"),false,(int)layers)
                &&"sustained_high_performance".equals(r.opt("power_mode_name")),"resolved hardware configuration");
        numbers(object(r,"sampler_requested"),new String[]{"temperature","top_p","top_k","repetition_penalty","seed"},
                new long[]{0,1,1,1,42});
        JSONObject sdk=object(r,"sdk_rc");
        need(number(sdk,"generate")==-200101,"caught SDK generation return code");
        String exception=exception(object(r,"sdk_exception_boundary"));
        need(exception.equals(exception(object(s,"sdk_exception_boundary"))),"request/session exception differs");
        JSONObject inputs=object(r,"input_sha256");inputHashes(inputs,e);
        JSONObject budget=object(r,"prompt_budget");
        need("llama_tokenize_exact_same_input_ids".equals(budget.opt("method"))
                &&e.config.profile.sha256.equals(budget.opt("model_contract_sha256"))
                &&ModelProfile.LLAMA_COMMIT.equals(budget.opt("tokenizer_source_commit")),"exact input-ID budget");
        truths(budget,"is_exact_token_count","checked","admitted","add_special","parse_special","input_ids_passed_directly");
        long count=number(budget,"prompt_tokens_exact");
        need(count>0&&count<=e.config.contextTokens&&ids!=null&&ids.length==count*4L
                &&formatted!=null&&formatted.length>0&&formatted.length<=262144,"private input lengths");
        utf8(formatted);
        numbers(budget,new String[]{"formatted_utf8_bytes","input_ids_count","generation_tokens","reserved_tokens","total_context_tokens","context_tokens"},
                new long[]{formatted.length,count,e.maxTokens,ConservativeTokenBudget.RESERVED,
                        count+e.maxTokens+ConservativeTokenBudget.RESERVED,e.config.contextTokens});
        need(count+e.maxTokens+ConservativeTokenBudget.RESERVED<=e.config.contextTokens,"admitted context bound");
        String formattedHash=hash(formatted),idsHash=hash(ids),rawHash=hash(raw);
        need(formattedHash.equals(r.opt("formatted_prompt_sha256"))&&idsHash.equals(budget.opt("input_ids_sha256")),"formatted input hashes");
        JSONObject paths=object(r,"prompt_evidence");
        need("hepta.private-prompt-evidence.v1".equals(paths.opt("schema"))&&paths.opt("complete")==Boolean.TRUE
                &&(e.runPath+"/formatted-prompt.txt").equals(paths.opt("formatted_file"))
                &&(e.runPath+"/formatted-input-ids.le32").equals(paths.opt("input_ids_file"))
                &&(e.runPath+"/prompt-evidence.json").equals(paths.opt("metadata_file")),"private evidence paths");
        need("hepta.private-prompt-evidence.v1".equals(p.opt("schema"))&&e.requestId.equals(p.opt("request_id"))
                &&e.config.profile.id.equals(p.opt("model_profile"))&&e.config.profile.sha256.equals(p.opt("model_sha256"))
                &&SDK_COMMIT.equals(p.opt("sdk_source_commit"))&&ModelProfile.LLAMA_COMMIT.equals(p.opt("llama_source_commit"))
                &&formattedHash.equals(p.opt("formatted_prompt_sha256"))&&idsHash.equals(p.opt("input_ids_sha256"))
                &&"uint32-little-endian".equals(p.opt("input_ids_encoding")),"private prompt record");
        numbers(p,new String[]{"formatted_prompt_bytes","input_ids_count","input_ids_bytes"},new long[]{formatted.length,count,ids.length});
        truths(p,"input_ids_will_be_passed_directly","add_special","parse_special","use_jinja","add_generation_prompt",
                "diagnostic_only","does_not_prove_generation_completed");
        falses(p,"chat_template_override","enable_thinking","native_tools_argument","action_authorized");
        need(isHash(p.opt("gguf_default_template_sha256"))&&number(p,"gguf_default_template_bytes")>0,"private template record");
        inputHashes(object(p,"source_input_sha256"),e);
        // raw_text_present describes produced text, not whether the published private file exists.
        // A caught exception may publish an empty file or a truncated callback prefix; neither is generation success.
        need(rawPresent&&raw!=null&&raw.length<=1048576,"published bounded raw file required");
        need((e.runPath+"/raw-text.txt").equals(r.opt("raw_text_file"))
                &&number(r,"raw_text_bytes")==raw.length&&rawHash.equals(r.opt("raw_text_sha256")),"raw output binding");
        boolean rawUtf8=true;try{utf8(raw);}catch(java.nio.charset.CharacterCodingException invalid){rawUtf8=false;}
        need(r.opt("raw_text_utf8")==Boolean.valueOf(rawUtf8),"raw UTF-8 flag");
        Object rawSource=r.opt("raw_text_source"),present=r.opt("raw_text_present"),truncated=r.opt("raw_text_truncated");
        long retained=number(r,"callback_bytes_retained"),callbacks=number(r,"callback_text_bytes");
        need(retained>=0&&retained<=1048576&&callbacks>=retained&&number(r,"callback_count")>=0,"callback evidence");
        need("absent".equals(rawSource)?present==Boolean.FALSE&&truncated==Boolean.FALSE&&raw.length==0&&retained==0:
                "callback_prefix".equals(rawSource)?present==Boolean.TRUE&&truncated==Boolean.TRUE&&raw.length>0&&retained==raw.length:
                "sdk_full_text".equals(rawSource)&&present==Boolean.TRUE&&truncated instanceof Boolean
                    &&(truncated==Boolean.FALSE||raw.length==1048576),"raw source");
        session(s,e);
        return new SdkExceptionFailure(e,hash(requestBytes),hash(sessionBytes),hash(evidenceBytes),
                formattedHash,idsHash,rawHash,object(r,"sdk_exception_boundary").getString("kind"));
    }
    boolean matches(LocalRuntimeConfig current,String generation,String taskId,long pid,int sent,int accepted,
            byte[] requestBytes,byte[] sessionBytes,boolean observed,Integer exit,boolean force)throws Exception{
        return current==config&&this.generation.equals(generation)&&this.taskId.equals(taskId)&&this.pid==pid
                &&sequence==sent&&this.accepted==accepted&&observed&&exit!=null&&exit.intValue()==70&&!force
                &&requestHash.equals(hash(requestBytes))&&sessionHash.equals(hash(sessionBytes));
    }
    JSONObject audit()throws Exception{
        return new JSONObject().put("schema","hepta.local-model.sdk-exception-failure.v1")
                .put("worker_generation",generation).put("task_id",taskId).put("request_id",requestId)
                .put("request_sequence",sequence).put("worker_pid",pid).put("native_request_sha256",requestHash)
                .put("native_session_sha256",sessionHash).put("prompt_evidence_sha256",promptEvidenceHash)
                .put("formatted_prompt_sha256",formattedHash).put("input_ids_sha256",inputIdsHash).put("raw_text_sha256",rawHash)
                .put("kind",kind).put("parent_wait_exit_code",70).put("sdk_cleanup_bound",true)
                .put("inference_completed",false).put("request_committed",false).put("action_authorized",false);
    }
    private static void session(JSONObject s,Expected e)throws Exception{
        need("hepta.geniex-task-session.result.v1".equals(s.opt("schema"))&&e.generation.equals(s.opt("worker_generation"))
                &&e.taskId.equals(s.opt("task_id")),"native session identity");
        truths(s,"model_metadata_unchanged_before_close","sdk_destroy_attempted","sdk_deinit_attempted");
        falses(s,"process_exit_observed","close_requested","control_channel_write_failed");
        numbers(s,new String[]{"pid","requests_received","requests_completed","model_hash_count","model_create_count","sdk_init_count",
                "model_reset_count","signal_observed","last_request_status","last_request_return_status","sdk_destroy_rc","sdk_deinit_rc",
                "control_done_attempts","control_done_delivered","control_channel_last_errno"},
                new long[]{e.pid,e.sequence,e.accepted,1,1,1,e.sequence,0,70,70,0,0,e.sequence,e.sequence,0});
    }
    private static String exception(JSONObject x)throws Exception{
        truths(x,"enabled","caught");falses(x,"automatic_retry");
        Object kind=x.opt("kind"),message=x.opt("message_ascii");
        need(("std_exception".equals(kind)||"other_cpp_exception".equals(kind))&&message instanceof String
                &&((String)message).length()<=511,"exception kind/message");
        String text=(String)message;
        for(int i=0;i<text.length();i++)need(text.charAt(i)>=32&&text.charAt(i)<=126,"exception ASCII");
        Object truncated=x.opt("message_truncated"),replaced=x.opt("message_non_ascii_replaced");
        need(truncated instanceof Boolean&&replaced instanceof Boolean,"exception flags");
        return kind+"\n"+truncated+"\n"+replaced+"\n"+text;
    }
    private static void inputHashes(JSONObject v,Expected e)throws Exception{
        need(e.promptHash.equals(v.opt("prompt")),"original prompt hash");
        optionalHash(v,"system",e.systemHash);optionalHash(v,"grammar",e.grammarHash);nullValue(v,"image");
    }
    private static void optionalHash(JSONObject v,String key,String hash)throws Exception{
        if(hash==null)nullValue(v,key);else need(hash.equals(v.opt(key)),"original "+key+" hash");
    }
    private static boolean validId(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    private static boolean isHash(Object s){return s instanceof String&&((String)s).matches("[0-9a-f]{64}");}
    private static void nullValue(JSONObject v,String key)throws Exception{need(v.has(key)&&v.opt(key)==JSONObject.NULL,"missing/null "+key);}
    private static void truths(JSONObject v,String...keys)throws Exception{for(String k:keys)need(v.opt(k)==Boolean.TRUE,"true "+k);}
    private static void falses(JSONObject v,String...keys)throws Exception{for(String k:keys)need(v.opt(k)==Boolean.FALSE,"false "+k);}
    private static void numbers(JSONObject v,String[]keys,long[]values)throws Exception{
        for(int i=0;i<keys.length;i++)need(number(v,keys[i])==values[i],"number "+keys[i]);
    }
    private static long number(JSONObject v,String key){
        Object n=v.opt(key);return n instanceof Integer||n instanceof Long?((Number)n).longValue():Long.MIN_VALUE;
    }
    private static JSONObject object(JSONObject v,String key)throws Exception{
        Object o=v.opt(key);need(o instanceof JSONObject,"object "+key);return (JSONObject)o;
    }
    private static JSONObject json(byte[] raw)throws Exception{
        need(raw!=null&&raw.length>0&&raw.length<=1048576,"bounded receipt");return new JSONObject(utf8(raw));
    }
    private static String utf8(byte[] raw)throws Exception{
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
    }
    private static String hash(byte[] raw)throws Exception{
        need(raw!=null,"missing bytes");byte[] h=MessageDigest.getInstance("SHA-256").digest(raw);
        StringBuilder b=new StringBuilder();for(byte x:h){int u=x&255;if(u<16)b.append('0');b.append(Integer.toHexString(u));}return b.toString();
    }
    private static void need(boolean condition,String reason)throws IOException{
        if(!condition)throw new IOException("SDK exception failure proof rejected: "+reason);
    }
}
