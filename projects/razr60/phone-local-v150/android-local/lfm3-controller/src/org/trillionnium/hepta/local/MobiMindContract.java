package org.trillionnium.hepta.local;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Pure-Java evidence contract. Raw model text is never parsed as a phone action. */
public final class MobiMindContract {
    private MobiMindContract() {}
    public static final class Expected {
        public final String requestId, promptSha, imageSha, mnnPath;
        public final int uid, parentPid, maxTokens, imageWidth, imageHeight;
        public final long promptBytes,imageBytes;
        public Expected(String id,int uid,int parent,String prompt,String image,String mnn,int max,int width,int height,long promptBytes,long imageBytes){
            if(id==null||!id.matches("[0-9a-f]{32}")||uid<10000||parent<=1
                    ||prompt==null||!prompt.matches("[0-9a-f]{64}")||image==null||!image.matches("[0-9a-f]{64}")
                    ||mnn==null||!mnn.startsWith("/data/app/")||max<1||max>512||width<1||height<1
                    ||promptBytes<1||promptBytes>65536||imageBytes<33||imageBytes>32*1024*1024)
                throw new IllegalArgumentException("invalid expected model-only identity");
            requestId=id;this.uid=uid;parentPid=parent;promptSha=prompt;imageSha=image;mnnPath=mnn;
            maxTokens=max;imageWidth=width;imageHeight=height;
            this.promptBytes=promptBytes;this.imageBytes=imageBytes;
        }
    }
    public static List<String> verify(Map<String,Object> receipt,Map<String,Object> terminal,
            Map<String,Object> tokens,Map<String,Object> modelFiles,byte[] raw,Expected x,int exitCode) {
        List<String> errors=new ArrayList<>();
        check(errors,exitCode==0,"exit_code");
        for(Map<String,Object> object:java.util.Arrays.asList(receipt,terminal)){
            equal(errors,object,"schema","hepta.mobimind.model_only.v1");
            equal(errors,object,"request_id",x.requestId);equal(errors,object,"outcome","completed");
            number(errors,object,"uid",x.uid);number(errors,object,"expected_parent_pid",x.parentPid);
            number(errors,object,"expected_exit_code",0);equal(errors,object,"receipt_complete",Boolean.TRUE);
            equal(errors,object,"actions_executed",Boolean.FALSE);equal(errors,object,"external_model_used",Boolean.FALSE);
            equal(errors,object,"http_resources_compiled",Boolean.FALSE);
        }
        check(errors,integer(receipt.get("pid"))>1&&receipt.get("pid").equals(terminal.get("pid")),"native_pid_consistency");
        equal(errors,receipt,"generation_complete",Boolean.TRUE);
        equal(errors,receipt,"model_repo",MobiMindPins.MODEL_REPO);equal(errors,receipt,"model_revision",MobiMindPins.MODEL_REVISION);
        equal(errors,receipt,"mnn_revision",MobiMindPins.MNN_REVISION);equal(errors,receipt,"loaded_mnn_path",x.mnnPath);
        equal(errors,receipt,"loaded_mnn_sha256",MobiMindPins.MNN_SHA);number(errors,receipt,"pinned_files_verified",11);
        equal(errors,receipt,"initial_input_binding",Boolean.TRUE);equal(errors,receipt,"post_generation_file_binding",Boolean.TRUE);
        for(String key:new String[]{"prompt_expected_sha256","prompt_actual_sha256"})equal(errors,receipt,key,x.promptSha);
        for(String key:new String[]{"image_expected_sha256","image_actual_sha256"})equal(errors,receipt,key,x.imageSha);
        equal(errors,receipt,"sampling","greedy");number(errors,receipt,"context_limit",4096);
        number(errors,receipt,"max_new_tokens",x.maxTokens);number(errors,receipt,"input_ids_hook_calls",1);
        long count=integer(receipt.get("input_tokens_exact"));
        check(errors,count>0&&count+x.maxTokens<=4096,"exact_context_budget");
        String idSha=receipt.get("input_ids_sha256") instanceof String?(String)receipt.get("input_ids_sha256"):"";
        check(errors,idSha.matches("[0-9a-f]{64}"),"input_ids_sha256");
        number(errors,tokens,"count",count);number(errors,tokens,"max_new_tokens",x.maxTokens);number(errors,tokens,"context_limit",4096);
        equal(errors,tokens,"encoding","signed-token-id-as-uint32-little-endian");equal(errors,tokens,"sha256",idSha);
        number(errors,receipt,"original_width",x.imageWidth);number(errors,receipt,"original_height",x.imageHeight);
        long width=integer(receipt.get("resized_width")),height=integer(receipt.get("resized_height"));
        check(errors,width>=32&&height>=32&&width<=1024&&height<=1024&&width%32==0&&height%32==0,"resized_geometry");
        equal(errors,receipt,"requested_text_backend","opencl");equal(errors,receipt,"requested_vision_backend","opencl");
        equal(errors,receipt,"opencl_preflight",Boolean.TRUE);equal(errors,receipt,"backend_probe_qualified",Boolean.TRUE);
        equal(errors,receipt,"gpu_execution_observed",Boolean.TRUE);equal(errors,receipt,"all_gpu_claim",Boolean.FALSE);
        check(errors,integer(receipt.get("opencl_runtime_selections"))>=2,"opencl_runtime_selections");
        check(errors,integer(receipt.get("opencl_execution_calls"))>0,"opencl_execution_calls");
        number(errors,receipt,"execution_errors",0);
        check(errors,integer(receipt.get("cpu_execution_calls"))>=0&&integer(receipt.get("other_execution_calls"))>=0,"helper_execution_counts");
        Map<String,Object> runtimes=object(receipt.get("runtime_selections"));
        long runtimeTotal=0;
        for(Map.Entry<String,Object> item:runtimes.entrySet()){
            long n=integer(item.getValue());check(errors,n>0,"runtime_count");
            if(item.getKey().endsWith(":3->3"))runtimeTotal+=n;
            if(item.getKey().contains(":3->")&&!item.getKey().endsWith(":3->3"))errors.add("opencl_runtime_fallback");
        }
        check(errors,runtimeTotal>=2&&runtimeTotal==integer(receipt.get("opencl_runtime_selections")),"runtime_count_consistency");
        Map<String,Object> operations=object(receipt.get("operation_backend_counts"));
        long gpu=0,cpu=0,other=0,operationErrors=0;
        for(Map.Entry<String,Object> item:operations.entrySet()){
            Map<String,Object> row=object(item.getValue());long calls=integer(row.get("calls")),failed=integer(row.get("error_calls"));
            check(errors,calls>0&&failed>=0&&failed<=calls,"operation_count");
            String[] fields=item.getKey().split(":",3);
            check(errors,fields.length>=2,"operation_backend_key");
            if(fields.length>=2){if("3".equals(fields[1]))gpu+=calls;else if("0".equals(fields[1])||"13".equals(fields[1]))cpu+=calls;else other+=calls;}
            operationErrors+=failed;
        }
        check(errors,gpu==integer(receipt.get("opencl_execution_calls"))&&cpu==integer(receipt.get("cpu_execution_calls"))
            &&other==integer(receipt.get("other_execution_calls"))&&operationErrors==0,"operation_count_consistency");
        equal(errors,receipt,"raw_valid_utf8",Boolean.TRUE);number(errors,receipt,"raw_bytes",raw.length);
        equal(errors,receipt,"raw_sha256",sha(raw));check(errors,raw.length>0&&raw.length<=1048576,"raw_size");
        try{utf8(raw);}catch(Exception failure){errors.add("raw_utf8");}
        Map<String,Object> context=object(receipt.get("mnn_context"));
        number(errors,context,"status",1); // Pinned llm.hpp: NORMAL_FINISHED = 1.
        check(errors,integer(context.get("output_token_count"))>0,"native_output_tokens");
        check(errors,modelFiles.size()==11,"model_binding_membership");
        for(MobiMindPins.FilePin pin:MobiMindPins.modelFiles()){
            Map<String,Object> row=object(modelFiles.get(pin.name));
            number(errors,row,"bytes",pin.bytes);equal(errors,row,"sha256",pin.sha256);
        }
        hashExecution(errors,receipt,modelFiles,x);
        return errors;
    }
    private static void hashExecution(List<String> errors,Map<String,Object> receipt,Map<String,Object> models,Expected x){
        Map<String,Object> dispatch=object(receipt.get("sha256_dispatch"));
        equal(errors,dispatch,"schema","hepta.mobimind.sha256-dispatch.v1");
        equal(errors,dispatch,"compiled_armv8_sha2",Boolean.TRUE);
        check(errors,dispatch.get("runtime_hwcap_sha2") instanceof Boolean,"runtime_hwcap_sha2_boolean");
        boolean hardware=Boolean.TRUE.equals(dispatch.get("runtime_hwcap_sha2"));
        long bytes=0,blocks=0;
        for(MobiMindPins.FilePin pin:MobiMindPins.modelFiles()){
            bytes+=pin.bytes;blocks+=(pin.bytes+72)/64;
            hashRow(errors,object(object(models.get(pin.name)).get("hash_execution")),pin.bytes,hardware,"model_hash:"+pin.name);
        }
        number(errors,dispatch,"model_files_hashed",11);number(errors,dispatch,"model_bytes_hashed",bytes);
        number(errors,dispatch,"model_hardware_blocks",hardware?blocks:0);number(errors,dispatch,"model_portable_blocks",hardware?0:blocks);
        equal(errors,dispatch,"hash_backend",hardware?"armv8-sha2":"portable");
        for(String key:new String[]{"complete_model_files_only","padding_included_in_block_counts","full_file_hash_each_request"})equal(errors,dispatch,key,Boolean.TRUE);
        equal(errors,dispatch,"digest_cache",Boolean.FALSE);
        hashRow(errors,object(dispatch.get("prompt")),x.promptBytes,hardware,"prompt_hash");
        hashRow(errors,object(dispatch.get("image")),x.imageBytes,hardware,"image_hash");
        hashRow(errors,object(dispatch.get("loaded_library")),MobiMindPins.MNN_BYTES,hardware,"loaded_library_hash");
    }
    private static void hashRow(List<String> errors,Map<String,Object> row,long bytes,boolean hardware,String label){
        int initial=errors.size();long blocks=(bytes+72)/64;
        number(errors,row,"bytes_hashed",bytes);number(errors,row,"hardware_blocks",hardware?blocks:0);number(errors,row,"portable_blocks",hardware?0:blocks);
        equal(errors,row,"hash_backend",hardware?"armv8-sha2":"portable");equal(errors,row,"complete",Boolean.TRUE);
        equal(errors,row,"selected_hardware",hardware);
        if(errors.size()!=initial)errors.add(label);
    }
    private static void equal(List<String> errors,Map<String,Object> value,String key,Object expected){check(errors,expected.equals(value.get(key)),key);}
    private static void number(List<String> errors,Map<String,Object> value,String key,long expected){check(errors,integer(value.get(key))==expected,key);}
    private static void check(List<String> errors,boolean valid,String key){if(!valid)errors.add(key);}
    private static long integer(Object value){return value instanceof Long||value instanceof Integer?((Number)value).longValue():Long.MIN_VALUE;}
    @SuppressWarnings("unchecked") public static Map<String,Object> object(Object value){return value instanceof Map?(Map<String,Object>)value:new LinkedHashMap<>();}
    public static String sha(byte[] bytes){
        try{byte[] hash=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder result=new StringBuilder(64);
            for(byte b:hash)result.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return result.toString();}
        catch(Exception failure){throw new IllegalStateException(failure);}
    }
    public static String utf8(byte[] bytes)throws Exception{
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }
    public static Map<String,Object> jsonObject(byte[] bytes)throws Exception{
        if(bytes.length>1048576)throw new IllegalArgumentException("JSON exceeds bound");
        Json parser=new Json(utf8(bytes));Object value=parser.value(0);parser.space();
        if(!(value instanceof Map)||parser.at!=parser.text.length())throw new IllegalArgumentException("one JSON object required");
        return object(value);
    }
    /** Strict receipt JSON: duplicate keys, nonfinite numbers, permissive literals and trailing data fail. */
    private static final class Json {
        final String text;int at,values;
        Json(String text){this.text=text;}
        void space(){while(at<text.length()&&" \r\n\t".indexOf(text.charAt(at))>=0)at++;}
        char take(){if(at>=text.length())throw new IllegalArgumentException("incomplete JSON");return text.charAt(at++);}
        void need(char c){space();if(take()!=c)throw new IllegalArgumentException("invalid JSON delimiter");}
        Object value(int depth){
            if(depth>32||++values>65536)throw new IllegalArgumentException("JSON nesting/member bound");space();char c=take();
            if(c=='"')return string();
            if(c=='{'){Map<String,Object> out=new LinkedHashMap<>();space();if(at<text.length()&&text.charAt(at)=='}'){at++;return out;}
                while(true){need('"');String key=string();if(out.containsKey(key))throw new IllegalArgumentException("duplicate JSON key");need(':');out.put(key,value(depth+1));space();char end=take();if(end=='}')return out;if(end!=',')throw new IllegalArgumentException("invalid JSON object");}}
            if(c=='['){List<Object> out=new ArrayList<>();space();if(at<text.length()&&text.charAt(at)==']'){at++;return out;}
                while(true){out.add(value(depth+1));space();char end=take();if(end==']')return out;if(end!=',')throw new IllegalArgumentException("invalid JSON array");}}
            int begin=at-1;while(at<text.length()&&" \r\n\t,]}".indexOf(text.charAt(at))<0)at++;
            String token=text.substring(begin,at);if("true".equals(token))return Boolean.TRUE;if("false".equals(token))return Boolean.FALSE;if("null".equals(token))return null;
            if(!token.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))throw new IllegalArgumentException("invalid JSON value");
            if(token.indexOf('.')<0&&token.indexOf('e')<0&&token.indexOf('E')<0)return Long.valueOf(token);
            double number=Double.parseDouble(token);if(!Double.isFinite(number))throw new IllegalArgumentException("nonfinite JSON number");return number;
        }
        String string(){StringBuilder out=new StringBuilder();while(true){char c=take();if(c=='"')break;if(c<32)throw new IllegalArgumentException("JSON control character");
            if(c=='\\'){char escaped=take();switch(escaped){case '"':case '\\':case '/':c=escaped;break;case 'b':c='\b';break;case 'f':c='\f';break;case 'n':c='\n';break;case 'r':c='\r';break;case 't':c='\t';break;
                case 'u':if(at+4>text.length()||!text.substring(at,at+4).matches("[0-9a-fA-F]{4}"))throw new IllegalArgumentException("invalid unicode escape");c=(char)Integer.parseInt(text.substring(at,at+4),16);at+=4;break;default:throw new IllegalArgumentException("invalid JSON escape");}}
            out.append(c);}
            for(int i=0;i<out.length();i++){char c=out.charAt(i);if(Character.isHighSurrogate(c)){if(++i>=out.length()||!Character.isLowSurrogate(out.charAt(i)))throw new IllegalArgumentException("unpaired unicode surrogate");}else if(Character.isLowSurrogate(c))throw new IllegalArgumentException("unpaired unicode surrogate");}
            return out.toString();}
    }
}
