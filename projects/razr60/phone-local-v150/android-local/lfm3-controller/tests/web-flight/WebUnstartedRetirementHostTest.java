package org.trillionnium.hepta.webprotocol;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.json.JSONArray;
import org.json.JSONObject;

/** Synthetic typed-retirement contracts only; no Android feature, storage or phone evidence. */
public final class WebUnstartedRetirementHostTest {
    private static int cases;
    private interface Change { void run(JSONObject record)throws Exception; }
    private static final String TASK=repeat("a",32),SESSION=repeat("b",64),ATTACH=repeat("c",64),CLOSE=repeat("d",64),NEXT=repeat("e",64);
    private static final String INSTANCE="10000000-0000-4000-8000-000000000001",GENERATION="20000000-0000-4000-8000-000000000002";
    public static void main(String[] args)throws Exception{
        JSONObject first=initial(WebEvidenceProtocol.HELPER_VERSION_CODE);String exact=first.toString();
        yes(pass(first),"complete never-started fixture");
        yes(exact.equals(first.toString())&&!first.getJSONObject("original_cleanup").getBoolean("webview_destroyed")
                &&!WebRecoveryPolicy.evaluateUnstartedRecord(first).getBoolean("storage_cleanup_called"),"original false cleanup preserved");
        JSONObject confirmation=confirmation(first);String exactConfirm=confirmation.toString();
        yes(pass(confirmation),"fresh confirmation of original exact proof");
        yes(exactConfirm.equals(confirmation.toString()),"confirmation replay does not mutate original");
        reject("construction was dispatched",r->r.getJSONObject("resource_fence_before").put("resource_creation_dispatched",true));
        reject("profile assignment was dispatched",r->r.getJSONObject("resource_fence_after").put("profile_assignment_dispatched",true));
        reject("page load attempted",r->r.getJSONObject("resource_fence_after").put("load_dispatch_count",1));
        reject("capture attempted",r->r.getJSONObject("resource_fence_before").put("capture_dispatch_count",1));
        reject("live WebView exists",r->r.getJSONObject("resource_fence_after").put("live_webview_count",1));
        reject("pending capture exists",r->r.getJSONObject("resource_fence_before").put("pending_capture_count",1));
        reject("original state was active",r->{JSONObject p=prior(r);p.put("state","active");putPrior(r,p);});
        reject("cleanup methods cannot be invented",r->{JSONObject p=prior(r);p.getJSONObject("cleanup").put("webview_destroyed",true);
            r.getJSONObject("original_cleanup").put("webview_destroyed",true);putPrior(r,p);});
        reject("process changed across fence",r->r.getJSONObject("process_identity_after").put("pid",222));
        reject("placeholder window differs",r->r.getJSONObject("resource_fence_before").put("placeholder_window_id",99));
        reject("navigation had started",r->{JSONObject p=prior(r);p.put("navigation_epoch",1);putPrior(r,p);});
        reject("attach happened after its deadline",r->{JSONObject p=prior(r);p.put("attach_bound_elapsed_ms",3001);putPrior(r,p);r.put("attach_bound_elapsed_ms",3001);});
        reject("close completed late",r->r.put("completed_elapsed_ms",5001));
        reject("decimal deadline is not an integer",r->{JSONObject q=new JSONObject(r.getString("request_json_utf8"));q.put("deadline_elapsed_ms",5000.5);putRequest(r,q);});
        reject("original attach bytes altered",r->r.put("attach_request_json_utf8",r.getString("attach_request_json_utf8")+" "));
        reject("foreign close task",r->{JSONObject q=new JSONObject(r.getString("request_json_utf8"));q.put("task_id",repeat("f",32));putRequest(r,q);});
        yes(!pass(initial(2)),"observer code2 is not the formal peer");
        reject("unknown record field",r->r.put("caller_verified",true));
        rejectConfirmation("initial record hash changed",r->r.put("initial_record_sha256",repeat("0",64)));
        rejectConfirmation("close nonce reused",r->{JSONObject q=new JSONObject(r.getString("request_json_utf8"));q.put("request_nonce",CLOSE);putRequest(r,q);});
        rejectConfirmation("current owned view exists",r->r.put("active_bound_view_count",1));
        rejectConfirmation("current capture exists",r->r.put("pending_capture_count",1));
        rejectConfirmation("actual helper identity changed",r->r.getJSONObject("actual_helper_identity").put("uid",10485));
        rejectConfirmation("confirmation completed late",r->r.put("completed_elapsed_ms",7001));
        rejectConfirmation("confirmation chain refused",r->{String nested=confirmation(initial(WebEvidenceProtocol.HELPER_VERSION_CODE)).toString()+"\n";
            r.put("initial_record_utf8",nested).put("initial_record_bytes",bytes(nested)).put("initial_record_sha256",digest(nested));});
        reject("cleanup field absent",r->r.remove("original_cleanup"));
        reject("original journal hash changed",r->r.put("prior_journal_sha256",repeat("0",64)));
        reject("fence backwards time",r->r.getJSONObject("resource_fence_after").put("observed_elapsed_ms",3999));
        reject("display0 is not the leased placeholder",r->r.getJSONObject("resource_fence_before").put("owned_display_id",0));
        reject("page was not retired",r->r.getJSONObject("resource_fence_after").put("retired",false));
        reject("placeholder predates lease",r->r.getJSONObject("resource_fence_before").put("activity_created_elapsed_ms",999));
        rejectConfirmation("current process UID foreign",r->r.getJSONObject("current_process_identity").put("uid",10485));
        if(cases!=36)throw new AssertionError("case inventory differs:"+cases);
        System.out.println(new JSONObject().put("schema","hepta.web-helper-unstarted-retirement-host-checks.v1")
                .put("passed",true).put("cases",cases).put("synthetic_fixtures",true).put("phone_tested",false)
                .put("android_api_callbacks_executed",false).put("business_verified",false).toString());
    }
    private static void reject(String name,Change change)throws Exception{
        JSONObject r=initial(WebEvidenceProtocol.HELPER_VERSION_CODE);change.run(r);yes(!pass(r),name);
    }
    private static void rejectConfirmation(String name,Change change)throws Exception{
        JSONObject r=confirmation(initial(WebEvidenceProtocol.HELPER_VERSION_CODE));change.run(r);yes(!pass(r),name);
    }
    private static boolean pass(JSONObject record)throws Exception{return WebRecoveryPolicy.evaluateUnstartedRecord(record).getBoolean("retirement_verified");}
    private static void yes(boolean condition,String name){cases++;if(!condition)throw new AssertionError(name);}
    private static JSONObject initial(int helperVersion)throws Exception{
        String owner="synthetic complete owner";JSONObject controller=identity(WebEvidenceProtocol.CONTROLLER_PACKAGE,10481,53),helper=identity(WebEvidenceProtocol.HELPER_PACKAGE,10484,helperVersion);
        JSONObject bg=new JSONObject().put("generation",GENERATION).put("display_id",15).put("display_name","hepta-bg-"+GENERATION)
                .put("boot_count",7).put("created_elapsed_ms",1000L).put("expires_elapsed_ms",10000L)
                .put("selected_packages",new JSONArray().put(WebEvidenceProtocol.HELPER_PACKAGE));
        JSONObject auth=new JSONObject().put("schema","synthetic contract fixture").put("allowed_tools",new JSONArray());
        JSONObject attach=new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ATTACH))
                .put("request_nonce",ATTACH).put("task_id",TASK).put("controller_session_nonce",SESSION).put("deadline_elapsed_ms",3000L)
                .put("owner",owner).put("owner_sha256",digest(owner)).put("contract_sha256",repeat("1",64))
                .put("authorization",auth).put("background",bg).put("controller_identity",controller).put("helper_identity",helper);
        String attachRaw=attach.toString();JSONObject binding=WebEvidenceBinding.fromAttach(attach);String bindingSha=WebEvidenceBinding.sha256(binding);
        JSONObject cleanup=new JSONObject().put("captures_retired",false).put("stop_loading_called",false)
                .put("webview_destroyed",false).put("active_view_absent",true).put("storage_clear_completed",false);
        JSONObject process=process(111,7,"11");
        JSONObject prior=new JSONObject().put("schema",WebEvidenceProtocol.JOURNAL_SCHEMA).put("state","unknown")
                .put("binding",copy(binding)).put("binding_sha256",bindingSha).put("helper_pid",111).put("process_identity",copy(process))
                .put("window_id",37).put("webview_instance",INSTANCE).put("navigation_epoch",0L)
                .put("cleanup",copy(cleanup)).put("storage_isolation",JSONObject.NULL)
                .put("attach_request_json_utf8",attachRaw).put("attach_request_sha256",digest(attachRaw)).put("attach_bound_elapsed_ms",2000L)
                .put("consumed_requests",new JSONObject().put(ATTACH,digest(attachRaw)));
        JSONObject r=new JSONObject().put("schema",WebEvidenceProtocol.UNSTARTED_SCHEMA)
                .put("binding",binding).put("binding_sha256",bindingSha).put("attach_request_json_utf8",attachRaw)
                .put("attach_request_sha256",digest(attachRaw)).put("attach_bound_elapsed_ms",2000L)
                .put("original_cleanup",cleanup).put("actual_controller_identity",copy(controller)).put("actual_helper_identity",copy(helper))
                .put("process_identity_before",copy(process)).put("process_identity_after",copy(process))
                .put("resource_fence_before",fence(4000L)).put("resource_fence_after",fence(4001L))
                .put("started_elapsed_ms",4000L).put("completed_elapsed_ms",4002L)
                .put("old_cleanup_methods_verified",false).put("business_verified",false);
        putRequest(r,close(CLOSE,5000));putPrior(r,prior);return r;
    }
    private static JSONObject confirmation(JSONObject first)throws Exception{
        String original=first.toString()+"\n";
        JSONObject r=new JSONObject().put("schema",WebEvidenceProtocol.UNSTARTED_CONFIRMATION_SCHEMA)
                .put("binding_sha256",first.getString("binding_sha256"))
                .put("initial_record_utf8",original).put("initial_record_bytes",bytes(original)).put("initial_record_sha256",digest(original))
                .put("actual_controller_identity",copy(first.getJSONObject("actual_controller_identity")))
                .put("actual_helper_identity",copy(first.getJSONObject("actual_helper_identity")))
                .put("current_process_identity",process(222,8,"22"))
                .put("started_elapsed_ms",6000L).put("completed_elapsed_ms",6001L)
                .put("active_bound_view_count",0).put("pending_capture_count",0)
                .put("old_cleanup_methods_verified",false).put("business_verified",false);
        putRequest(r,close(NEXT,7000));return r;
    }
    private static JSONObject close(String nonce,long deadline)throws Exception{return new JSONObject()
            .put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CLOSE)).put("request_nonce",nonce)
            .put("task_id",TASK).put("controller_session_nonce",SESSION).put("deadline_elapsed_ms",deadline).put("reason","error");}
    private static JSONObject identity(String pkg,int uid,int version)throws Exception{return new JSONObject()
            .put("package",pkg).put("uid",uid).put("version_code",version)
            .put("apk_hashes",new JSONObject().put("/synthetic/base.apk",repeat("2",64)))
            .put("apk_set_sha256",repeat("3",64)).put("signer_sha256",WebEvidenceProtocol.SIGNER_SHA256);}
    private static JSONObject process(int pid,int boot,String token)throws Exception{return new JSONObject()
            .put("schema","hepta.web-helper.process-identity.v1").put("pid",pid).put("uid",10484)
            .put("process_name",WebEvidenceProtocol.HELPER_PACKAGE).put("boot_count",boot).put("recorded_elapsed_ms",500L)
            .put("state_summary_hex",repeat(token,32)).put("state_summary_registered",true).put("state_summary_registration_error",JSONObject.NULL);}
    private static JSONObject fence(long observed)throws Exception{return new JSONObject().put("schema",WebEvidenceProtocol.UNSTARTED_FENCE_SCHEMA)
            .put("observed_elapsed_ms",observed).put("activity_created_elapsed_ms",1500L).put("planned_webview_instance",INSTANCE)
            .put("placeholder_window_id",37).put("owned_display_id",15).put("bound_page",true).put("retired",true)
            .put("resource_creation_dispatched",false).put("profile_assignment_dispatched",false)
            .put("load_dispatch_count",0).put("capture_dispatch_count",0).put("webview_present",false)
            .put("capture_present",false).put("profile_present",false).put("preparing",false)
            .put("live_webview_count",0).put("pending_capture_count",0);}
    private static JSONObject prior(JSONObject r)throws Exception{return new JSONObject(r.getString("prior_journal_utf8"));}
    private static void putPrior(JSONObject r,JSONObject prior)throws Exception{
        String raw=prior.toString()+"\n",hash=digest(raw);
        r.put("prior_journal_utf8",raw).put("prior_journal_bytes",bytes(raw)).put("prior_journal_sha256",hash)
                .put("preserved_prior_record",new JSONObject().put("name","unresolved-journal-"+hash+".json").put("bytes",bytes(raw)).put("sha256",hash));
    }
    private static void putRequest(JSONObject r,JSONObject request)throws Exception{
        String raw=request.toString();r.put("request_json_utf8",raw).put("request_sha256",digest(raw));
    }
    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    private static int bytes(String value){return value.getBytes(StandardCharsets.UTF_8).length;}
    private static String repeat(String value,int count){StringBuilder out=new StringBuilder();for(int i=0;i<count;i++)out.append(value);return out.toString();}
    private static String digest(String value)throws Exception{byte[] raw=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder();for(byte b:raw)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();}
}
