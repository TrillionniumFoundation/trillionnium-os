package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;

/** Full production receipt verifier, with synthetic or saved Binder UID/time inputs. */
public final class WebPreDispatchReceiptHostTest {
    static final String TASK=repeat('1',32),SESSION=repeat('2',64),NONCE=repeat('3',64);
    static final String INSTANCE="12345678-1234-1234-1234-123456789012",GENERATION="22345678-1234-1234-1234-123456789012";
    static int assertions,cases;static JSONArray names=new JSONArray();
    interface Work{void run()throws Exception;}
    static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static String repeat(char c,int n){char[] a=new char[n];Arrays.fill(a,c);return new String(a);}
    static void test(String name,Work work)throws Exception{work.run();cases++;names.put(name);}
    static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    static JSONObject binding()throws Exception{
        String owner="网页查询测试：在南航官方网站查询2026年11月17日北京到上海的单程航班，1名成人。"+WebFlightGoal.BACKGROUND_TAIL;
        WebFlightGoal goal=WebFlightGoal.parse(owner);
        JSONObject bg=new JSONObject().put("generation",GENERATION).put("display_id",7).put("display_name","hepta-bg-"+GENERATION)
                .put("boot_count",1).put("created_elapsed_ms",500).put("expires_elapsed_ms",10000)
                .put("selected_packages",new JSONArray().put(WebEvidenceProtocol.HELPER_PACKAGE));
        Map<String,Object> authMap=TaskAuthorization.parse(owner).evidence();JSONObject auth=new JSONObject(authMap);
        for(Map.Entry<String,Object> row:authMap.entrySet())if(row.getValue()==null)auth.put(row.getKey(),JSONObject.NULL);
        return WebEvidenceBinding.fromAttach(new JSONObject().put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("owner",owner).put("owner_sha256",goal.ownerSha256).put("contract_sha256",goal.contractSha256)
                .put("authorization",auth).put("background",bg)
                .put("controller_identity",new JSONObject().put("uid",10481))
                .put("helper_identity",new JSONObject().put("uid",10484).put("version_code",WebEvidenceProtocol.HELPER_VERSION_CODE)));
    }
    static JSONObject request()throws Exception{return new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CAPTURE))
            .put("task_id",TASK).put("controller_session_nonce",SESSION).put("request_nonce",NONCE).put("deadline_elapsed_ms",2000)
            .put("expected_webview_instance",INSTANCE).put("expected_navigation_epoch",7);}
    static JSONObject callback(JSONObject binding)throws Exception{return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA)
            .put("method","captureEvidence").put("task_id",TASK).put("controller_session_nonce",SESSION).put("request_nonce",NONCE)
            .put("status","unavailable").put("reason","DOM changed across visual callback").put("actual_helper_uid",10484)
            .put("actual_display_id",7).put("actual_window_id",19).put("webview_instance",INSTANCE).put("navigation_epoch",7)
            .put("binding_sha256",WebEvidenceBinding.sha256(binding)).put("raw_length",0).put("raw_sha256",JSONObject.NULL)
            .put("retired",false).put("cleanup",JSONObject.NULL).put("recovery",JSONObject.NULL);}
    static WebEvidenceReceipt verify(JSONObject req,JSONObject b,JSONObject c,long received)throws Exception{
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,c.toString(),null,10484,1000,received);
    }
    static void refuse(JSONObject req,JSONObject b,JSONObject c,long received)throws Exception{
        boolean rejected=false;try{verify(req,b,c,received);}catch(Exception expected){rejected=true;}check(rejected,"invalid callback accepted");
    }
    public static void main(String[] args)throws Exception{
        JSONObject b=binding();
        test("metadata-only unavailable is independently verified",()->{WebEvidenceReceipt r=verify(request(),b,callback(b),1500);
            check("unavailable".equals(r.status)&&r.capture()==null&&r.evidenceRaw()==null,"no capture/page authority");
            check(!r.cleanupKnown&&!r.recovered&&!r.unstarted,"no cleanup authority");});
        String[] keys={"task_id","controller_session_nonce","request_nonce","method","schema","binding_sha256","webview_instance","actual_helper_uid","actual_display_id","actual_window_id","navigation_epoch","retired","raw_length","raw_sha256","cleanup","recovery"};
        Object[] values={repeat('8',32),repeat('8',64),repeat('8',64),"closeLease","unknown",repeat('8',64),"32345678-1234-1234-1234-123456789012",10485,0,-1,8,true,1,repeat('8',64),new JSONObject(),new JSONObject()};
        for(int i=0;i<keys.length;i++){final int n=i;test("verifier refuses changed "+keys[i],()->{JSONObject c=callback(b);c.put(keys[n],values[n]);refuse(request(),b,c,1500);});}
        test("late reply refused",()->refuse(request(),b,callback(b),2001));
        test("wrong expected epoch refused",()->{JSONObject r=request();r.put("expected_navigation_epoch",6);refuse(r,b,callback(b),1500);});
        test("duplicate callback key refused",()->{String raw=callback(b).toString();raw=raw.substring(0,raw.length()-1)+",\"retired\":false}";boolean refused=false;
            try{WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,request().toString(),b,raw,null,10484,1000,1500);}catch(Exception expected){refused=true;}check(refused,"duplicate callback accepted");});
        JSONArray actual=new JSONArray();
        if(args.length>1){
            Path helper=Paths.get(args[1]);JSONObject attach=null;List<Path> requests=new ArrayList<Path>();
            try(DirectoryStream<Path> stream=Files.newDirectoryStream(helper,"request-*.json")){for(Path p:stream)requests.add(p);}
            for(Path p:requests){JSONObject j=read(p);if("attachLease".equals(j.getString("method")))attach=new JSONObject(j.getString("request_json_utf8"));}
            check(attach!=null,"actual attach missing");JSONObject actualBinding=WebEvidenceBinding.fromAttach(attach);
            for(Path p:requests){JSONObject req=read(p);if(!"captureEvidence".equals(req.getString("method")))continue;
                Path rp=p.resolveSibling(p.getFileName().toString().replace("request-","reply-"));JSONObject reply=read(rp);
                JSONObject cb=new JSONObject(reply.getString("callback_json_utf8"));
                if(!"unavailable".equals(cb.getString("status"))||!"DOM changed across visual callback".equals(cb.opt("reason")))continue;
                check(reply.getBoolean("callback_verification_passed")&&reply.getLong("raw_bytes")==0,"saved phone callback/raw provenance");
                String reqRaw=req.getString("request_json_utf8"),cbRaw=reply.getString("callback_json_utf8");
                check(WebEvidenceJson.sha(reqRaw).equals(req.getString("request_sha256"))&&WebEvidenceJson.sha(cbRaw).equals(reply.getString("callback_sha256")),"exact original byte hashes");
                WebEvidenceReceipt r=WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,reqRaw,actualBinding,cbRaw,null,
                        actualBinding.getJSONObject("helper_identity").getInt("uid"),req.getLong("recorded_elapsed_ms"),reply.getLong("recorded_elapsed_ms"));
                check("unavailable".equals(r.status)&&r.capture()==null,"actual metadata-only refusal preserved");
                actual.put(new JSONObject().put("request_file_sha256",WebEvidenceJson.sha(Files.readAllBytes(p)))
                        .put("reply_file_sha256",WebEvidenceJson.sha(Files.readAllBytes(rp)))
                        .put("receipt_replay_passed",true).put("retry_predicate_reason_matched",true)
                        .put("live_binder_authentication_reperformed",false).put("page_or_action_accepted",false));
            }
            check(actual.length()==1,"exactly the one known original pre-dispatch failure required");
        }
        JSONObject out=new JSONObject().put("passed",true).put("synthetic_cases",cases).put("assertions",assertions).put("names",names)
                .put("actual_saved_callbacks",actual).put("actual_saved_callback_count",actual.length()).put("phone_commands",0);
        Files.write(Paths.get(args[0]),(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(out.toString());
    }
}
