package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Original private startup failure bytes are supplied by the caller. They are
 * never embedded in the repository. Current clock, installation and census
 * values in this host test are explicit fixtures, not device cleanup proof. */
public final class PublicProfileStartupAbsenceHostTest {
    static final String ID="88888888-4444-4444-8444-123456789abc";
    static final String HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static final JSONArray names=new JSONArray();
    static Map<String,byte[]> originals;static long now;static int boot,uid,display,root,leaf;
    static String token;static int assertions;
    interface Work{void run()throws Exception;}
    interface Change{void apply(JSONObject value)throws Exception;}
    static void need(boolean ok,String reason){assertions++;if(!ok)throw new AssertionError(reason);}
    static void yes(String name,Work work)throws Exception{work.run();names.put(name);}
    static JSONObject object(byte[] raw)throws Exception{return PublicProfileAbsenceRecovery.object(raw);}
    static byte[] bytes(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    static JSONObject clone(JSONObject value){return new JSONObject(value.toString());}
    static Map<String,byte[]> copy(){Map<String,byte[]> m=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,byte[]> e:originals.entrySet())m.put(e.getKey(),e.getValue().clone());return m;}
    static JSONObject controller()throws Exception{return PublicProfilePostlaunchAbsenceHostTest.controller().put("uid",uid);}
    static PublicProfileAbsenceRecovery.Request request(Map<String,byte[]> m)throws Exception{return PublicProfileAbsenceRecovery.postlaunchRequest(m,controller(),uid,ID,now,boot);}
    static void reject(String name,String code,Map<String,byte[]> m)throws Exception{
        try{request(m);throw new AssertionError("invalid startup recovery accepted: "+name);}
        catch(java.io.IOException expected){need(code.equals(expected.getMessage()),"wrong rejection for "+name+": "+expected.getMessage());}
        names.put(name);
    }
    static Map<String,byte[]> one(String key,Change change)throws Exception{
        Map<String,byte[]> m=copy();JSONObject v=object(m.get(key));change.apply(v);m.put(key,bytes(v));return m;
    }
    static void bindResult(Map<String,byte[]> m,JSONObject cleanup)throws Exception{
        m.put("cleanup",bytes(cleanup));JSONObject result=object(m.get("result")),session=clone(cleanup);
        session.remove("cleanup_known");session.remove("cleanup_error");
        result.put("background_cleanup",clone(cleanup)).put("background_session",session);m.put("result",bytes(result));
    }
    static Map<String,byte[]> response(Change change)throws Exception{
        Map<String,byte[]> m=copy();JSONObject b=object(m.get("bootstrap")),c=object(m.get("cleanup"));
        JSONObject response=b.getJSONObject("last_broker_response");change.apply(response);
        c.put("last_broker_response",clone(response));m.put("bootstrap",bytes(b));bindResult(m,c);return m;
    }
    static Map<String,byte[]> readback(Change change)throws Exception{
        Map<String,byte[]> m=copy();JSONObject b=object(m.get("bootstrap")),c=object(m.get("cleanup"));
        JSONObject readback=b.getJSONObject("app_display_readback");change.apply(readback);
        c.put("app_display_readback",clone(readback));m.put("bootstrap",bytes(b));bindResult(m,c);return m;
    }
    static Map<String,byte[]> terminal(Change change)throws Exception{
        Map<String,byte[]> m=copy();JSONObject t=object(m.get("broker_output"));change.apply(t);byte[] raw=bytes(t);
        JSONObject broker=object(m.get("broker_receipt"));
        broker.put("stored_bytes",raw.length).put("observed_bytes",raw.length).put("stored_sha256",ProfileIdentity.sha(raw));
        m.put("broker_output",raw);m.put("broker_receipt",bytes(broker));
        JSONObject cleanup=object(m.get("cleanup"));cleanup.put("broker_output",clone(broker));bindResult(m,cleanup);return m;
    }
    static void load(Path path)throws Exception{
        originals=new LinkedHashMap<String,byte[]>();JSONObject refs=new JSONObject(new String(Files.readAllBytes(path.resolve("ORIGINALS.json")),StandardCharsets.UTF_8));
        for(String key:new String[]{"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output"}){
            byte[] raw=Files.readAllBytes(path.resolve(key+".bin"));originals.put(key,raw);
            need(refs.getJSONObject(key).getString("sha256").equals(ProfileIdentity.sha(raw))&&refs.getJSONObject(key).getInt("bytes")==raw.length,"archived input differs");
        }
        JSONObject j=object(originals.get("journal")),t=object(originals.get("broker_output"));
        now=j.getLong("expires_elapsed_ms")+3000;boot=j.getInt("boot_count");uid=j.getInt("app_uid");display=j.getInt("display_id");
        JSONObject owned=t.getJSONObject("profile_cleanup").getJSONArray("owned_tasks").getJSONObject(0);
        root=owned.getInt("parent_task_id");leaf=owned.getInt("task_id");token=owned.getString("task_token_id");
        PublicProfilePostlaunchAbsenceHostTest.load(path);
    }
    static void rejectProof(String name,String code,Change change)throws Exception{
        PublicProfileAbsenceRecovery.Request r=request(copy());JSONObject p=PublicProfilePostlaunchAbsenceHostTest.proof(r);change.apply(p);
        try{PublicProfileAbsenceRecovery.validate(p,r,now+4025,boot);throw new AssertionError("invalid fresh absence proof accepted");}
        catch(java.io.IOException expected){need(code.equals(expected.getMessage()),"wrong proof refusal: "+expected.getMessage());}names.put(name);
    }
    public static void main(String[] args)throws Exception{
        load(Paths.get(args[0]));
        yes("actual ACTIVE APP_READY startup is bound to its later owned-process release",()->{
            JSONObject b=object(originals.get("bootstrap")),r=b.getJSONObject("last_broker_response");
            need("ACTIVE".equals(b.getString("state"))&&b.getBoolean("retired"),"actual bootstrap shape differs");
            need("prepare_state".equals(r.getString("operation"))&&"APP_READY".equals(r.getString("profile_permission_preparation_state")),"actual last response differs");
            PublicProfileAbsenceRecovery.Request request=request(copy());
            need(request.postlaunch&&request.displayId==display&&request.ownedRootTaskId==root&&request.ownedLeafTaskId==leaf&&token.equals(request.ownedLeafTaskToken),"recorded ownership changed");
        });
        yes("canonical request roundtrip retains all seven original byte sequences",()->{
            PublicProfileAbsenceRecovery.Request a=request(copy()),b=PublicProfileAbsenceRecovery.fromWire(a.wire());
            need(a.originalsSha256.equals(b.originalsSha256)&&a.wire().equals(b.wire()),"wire changed");
            for(String k:originals.keySet())need(Arrays.equals(originals.get(k),b.original(k)),"original archive changed");
        });
        yes("a separately bound current repaired APK is accepted without rewriting failed task",()->{
            JSONObject c=controller().put("source_sha256",ProfileIdentity.sha("explicit repaired host APK"))
                .put("source_path","/data/app/host-repaired-fixture/base.apk");
            PublicProfileAbsenceRecovery.Request r=PublicProfileAbsenceRecovery.postlaunchRequest(copy(),c,uid,ID,now,boot);
            need(PublicProfileAbsenceRecovery.same(c,r.controller())&&Arrays.equals(originals.get("result"),r.original("result")),"current repair changed historical task");
        });
        yes("fresh absence is still separately required",()->{
            PublicProfileAbsenceRecovery.Request r=request(copy());
            PublicProfileAbsenceRecovery.validate(PublicProfilePostlaunchAbsenceHostTest.proof(r),r,now+4025,boot);
            need(r.ownedRootTaskId==root&&r.ownedLeafTaskId==leaf,"fresh proof changed identity");
        });
        reject("unretired ACTIVE app cannot recover","PUBLIC_RECOVERY_BOOTSTRAP_STATE",one("bootstrap",v->v.put("retired",false)));
        reject("CLOSING bootstrap is outside this branch","PUBLIC_RECOVERY_BOOTSTRAP_STATE",one("bootstrap",v->v.put("state","CLOSING")));
        for(String op:new String[]{"create","launch","prepare_click","prepare_done","refresh","close"}){
            reject("different last RPC is refused: "+op,"PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("operation",op)));
        }
        reject("unsuccessful historical response refused","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("ok",false)));
        reject("historical dispatched effect refused","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("dispatched",true)));
        reject("READY preparation state cannot be guessed","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("profile_permission_preparation_state","WAITING")));
        reject("preparation admission already over refused","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("profile_permission_preparing",false)));
        reject("missing current installation verification refused","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("profile_current_identity_verified",false)));
        reject("active response cannot claim released cleanup","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("profile_cleanup_known",true)));
        reject("active response cannot contain a failure field","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("error","PUBLIC_SCOPE_POLICY_UNAVAILABLE")));
        reject("active response cannot contain a terminal reason","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("terminal_reason","PUBLIC_SCOPE_POLICY_UNAVAILABLE")));
        reject("retired broker response cannot be treated as active startup","PUBLIC_STARTUP_ORIGINAL_ACTIVE_RESPONSE",response(v->v.put("public_scope_admission_retired",true)));
        reject("historical app readback hash must match actual canonical root readback","PUBLIC_STARTUP_AUTHENTICATED_READBACK",readback(v->v.put("broker_readback_sha256",HASH)));
        reject("historical app request id must match root readback","PUBLIC_STARTUP_AUTHENTICATED_READBACK",readback(v->v.put("broker_request_id",ID)));
        reject("historical app readback cannot precede root proof","PUBLIC_STARTUP_AUTHENTICATED_READBACK",readback(v->v.put("observed_started_elapsed_ms",0)));
        reject("early profile absence cannot be asserted retroactively","PUBLIC_STARTUP_CLEANUP_TRANSITION",response(v->v.getJSONObject("profile_cleanup").put("live_tasks_absent",true)));
        reject("early owned token must equal terminal token","PUBLIC_STARTUP_OWNED_IDENTITY_CHANGED",response(v->v.getJSONObject("profile_cleanup").getJSONArray("owned_tasks").getJSONObject(0).put("task_token_id",ID)));
        reject("early root identity cannot change during cleanup","PUBLIC_STARTUP_OWNED_IDENTITY_CHANGED",response(v->v.getJSONObject("profile_cleanup").getJSONArray("owned_tasks").getJSONObject(0).put("parent_task_id",root+1)));
        reject("early cookie verification cannot be missing","PUBLIC_STARTUP_LEAF_IDENTITY_CHANGED",response(v->v.getJSONObject("profile_last_leaf_validation").put("launch_cookie_present",false)));
        reject("early full UID cannot differ","PUBLIC_STARTUP_LEAF_IDENTITY_CHANGED",response(v->v.getJSONObject("profile_last_leaf_validation").put("observed_full_uid",uid)));
        reject("early protected history cannot differ","PUBLIC_STARTUP_HISTORY_IDENTITY_CHANGED",response(v->v.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("protected_history_sha256",HASH)));
        reject("early history time cannot go backwards","PUBLIC_STARTUP_HISTORY_IDENTITY_CHANGED",response(v->v.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("current_elapsed_ms",0)));
        reject("terminal must independently confirm release","PUBLIC_POSTLAUNCH_ORIGINAL_TERMINAL",terminal(v->v.put("release_confirmed",false)));
        reject("terminal cleanup must independently confirm live absence","PUBLIC_POSTLAUNCH_ORIGINAL_PROFILE_CLEANUP",terminal(v->v.getJSONObject("profile_cleanup").put("live_tasks_absent",false)));
        reject("terminal must retain verified task cookie","PUBLIC_POSTLAUNCH_ORIGINAL_LEAF_CHECK",terminal(v->v.getJSONObject("profile_last_leaf_validation").put("launch_cookie_present",false)));
        reject("observed process exit remains mandatory","PUBLIC_RECOVERY_BROKER_EXIT_UNPROVED",one("cleanup",v->v.put("broker_process_exit_observed",false)));
        reject("final owned process exit must be zero","PUBLIC_POSTLAUNCH_BROKER_EXIT",one("cleanup",v->v.put("broker_process_exit_code",1)));
        reject("model steps remain disallowed","PUBLIC_RECOVERY_BUSINESS_OR_MODEL_DISPATCH",one("result",v->v.put("steps",1)));
        reject("started model remains disallowed","PUBLIC_RECOVERY_MODEL_SESSION",one("result",v->v.getJSONObject("model_session").put("process_started",true)));
        reject("tool attempt remains disallowed","PUBLIC_RECOVERY_EFFECT_ATTEMPT",one("result",v->v.getJSONArray("fixed_intent_attempts").put(new JSONObject())));
        reject("pending action worker remains disallowed","PUBLIC_RECOVERY_WORKER_PENDING",one("result",v->v.put("action_worker_pending_at_terminal",true)));
        rejectProof("historical release does not imply current absence","PUBLIC_RECOVERY_PROOF_FLAGS",v->v.put("current_absence_verified",false));
        rejectProof("historical release does not authorize model resume","PUBLIC_RECOVERY_PROOF_FLAGS",v->v.put("automatic_resume",true));
        rejectProof("reused recorded root blocks fresh recovery","PUBLIC_POSTLAUNCH_OWNED_ID_REUSED",v->v.getJSONObject("before").getJSONObject("live").getJSONArray("all_task_ids").put(0,root));
        rejectProof("reused recorded leaf blocks fresh recovery","PUBLIC_POSTLAUNCH_OWNED_ID_REUSED",v->v.getJSONObject("after").getJSONObject("live").getJSONArray("all_task_ids").put(0,leaf));
        rejectProof("reused recorded display blocks fresh recovery","PUBLIC_POSTLAUNCH_DISPLAY_ID_REUSED",v->v.getJSONObject("after").getJSONObject("displays").put("recorded_id_absent",false));
        rejectProof("current controller must remain the same through recovery","PUBLIC_RECOVERY_PROOF_BINDING",v->v.getJSONObject("current_controller").put("source_sha256",ProfileIdentity.sha("another apk")));
        System.out.println(new JSONObject().put("schema","hepta.public-startup-absence-host-tests.v1").put("all_pass",true)
                .put("cases",names.length()).put("assertions",assertions).put("case_names",names)
                .put("actual_archived_failure_bytes",true).put("current_framework_clock_and_installation_synthetic",true)
                .put("phone_contacted",false).put("device_marker_modified",false).put("original_task_result_rewritten",false)
                .put("model_or_business_reissued",false).put("wire_bytes",request(copy()).wire().length()));
    }
}
