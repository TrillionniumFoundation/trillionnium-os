package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact a4 failure bytes and archived recents; current clock/PM/Binder samples
 * are explicitly synthetic. This never supplies a device recovery receipt. */
public final class PublicProfilePostlaunchAbsenceHostTest {
    private static final String HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String ID="88888888-4444-4444-8444-123456789abc";
    private static final JSONArray names=new JSONArray();
    private static Map<String,byte[]> originals;
    private static String before,after;private static long now;private static int boot;
    interface Work {void run()throws Exception;}
    interface Change {void change(JSONObject value)throws Exception;}
    private static void yes(String name,Work work)throws Exception{work.run();names.put(name);}
    private static void no(String name,Work work)throws Exception{try{work.run();}catch(Exception refused){names.put(name);return;}throw new AssertionError("accepted: "+name);}
    private static void need(boolean value){if(!value)throw new AssertionError("postlaunch host assertion");}
    private static JSONObject object(byte[] b)throws Exception{return PublicProfileAbsenceRecovery.object(b);}
    private static Map<String,byte[]> copy(){Map<String,byte[]> out=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,byte[]> e:originals.entrySet())out.put(e.getKey(),e.getValue().clone());return out;}
    private static Map<String,byte[]> change(String key,Change change)throws Exception{Map<String,byte[]> out=copy();JSONObject v=object(out.get(key));change.change(v);out.put(key,v.toString().getBytes(StandardCharsets.UTF_8));return out;}
    public static JSONObject controller()throws Exception{return new JSONObject().put("schema","hepta.recovery-controller-installation.v1")
            .put("package",PublicProfileAbsenceRecovery.CONTROLLER).put("user_id",0).put("uid",10481)
            .put("source_path","/data/app/host-fixture/base.apk").put("source_bytes",22000000).put("source_sha256",HASH)
            .put("version_code",70).put("signer_sha256",new JSONArray().put(HASH));}
    private static PublicProfileAbsenceRecovery.Request request(Map<String,byte[]> inputs)throws Exception{
        return PublicProfileAbsenceRecovery.postlaunchRequest(inputs,controller(),10481,ID,now,boot);
    }
    public static void load(Path directory)throws Exception{
        originals=new LinkedHashMap<String,byte[]>();
        for(String key:new String[]{"journal","owner","bootstrap","cleanup","result","broker_receipt","broker_output"})
            originals.put(key,Files.readAllBytes(directory.resolve(key+".bin")));
        JSONObject refs=new JSONObject(new String(Files.readAllBytes(directory.resolve("ORIGINALS.json")),StandardCharsets.UTF_8));
        for(String key:originals.keySet())need(ProfileIdentity.sha(originals.get(key)).equals(refs.getJSONObject(key).getString("sha256"))
                &&originals.get(key).length==refs.getJSONObject(key).getInt("bytes"));
        JSONObject j=object(originals.get("journal"));now=j.getLong("expires_elapsed_ms")+3000;boot=j.getInt("boot_count");
        before=new String(Files.readAllBytes(directory.resolve("before-recents.stdout")),StandardCharsets.UTF_8);
        after=new String(Files.readAllBytes(directory.resolve("after-recents.stdout")),StandardCharsets.UTF_8);
    }
    private static JSONObject sample(PublicProfileAbsenceRecovery.Request r,long at,String raw)throws Exception{
        return new JSONObject().put("started_elapsed_ms",at).put("finished_elapsed_ms",at+3).put("target_sha256",r.target.sha256)
                .put("process",new JSONObject().put("complete",true).put("old_creator_absent",true).put("started_elapsed_ms",at+1).put("finished_elapsed_ms",at+2)
                    .put("self_pid",43210).put("self_start_ticks",123456L).put("process_count",512).put("inspected_count",35).put("inventory_sha256",HASH))
                .put("live",new JSONObject().put("complete",true).put("root_count",5).put("leaf_count",4).put("snapshot_sha256",HASH)
                    .put("target_user_id",10).put("target_task_ids",new JSONArray()).put("all_task_ids",new JSONArray(Arrays.asList(1,2,3,4,5,1093,1094,1095,1256)))
                    .put("recorded_owned_ids_absent",true).put("recorded_display_empty",true))
                .put("recents",new JSONObject(PublicProfileRecentHistory.absence(raw,r.target).evidence()))
                .put("displays",new JSONObject().put("complete",true).put("count",2).put("snapshot_sha256",HASH).put("exact_name_absent",true).put("recorded_id_absent",true))
                .put("physical",new JSONObject().put("0",HASH).put("1",HASH));
    }
    public static JSONObject proof(PublicProfileAbsenceRecovery.Request r)throws Exception{
        return new JSONObject().put("schema",r.proofSchema()).put("source",r.source()).put("request_id",r.requestId).put("task_id",r.taskId)
                .put("generation",r.generation).put("owner_uid",r.ownerUid).put("owner_sha256",r.ownerSha256).put("journal_sha256",r.journalSha256)
                .put("originals_sha256",r.originalsSha256).put("original_inputs",r.inputHashes()).put("public_scope_wire",r.publicScope.wire())
                .put("public_scope_sha256",r.publicScope.sha256).put("profile_target_wire",r.target.wire()).put("target_sha256",r.target.sha256)
                .put("display_name",r.displayName).put("old_boot_count",r.oldBoot).put("current_boot_count",r.requestBoot)
                .put("lease_expires_elapsed_ms",r.expires).put("request_started_elapsed_ms",r.started).put("started_elapsed_ms",r.started+1)
                .put("finished_elapsed_ms",r.started+4020).put("deadline_elapsed_ms",r.deadline).put("current_controller",r.controller())
                .put("before",sample(r,r.started+5,before)).put("after",sample(r,r.started+4010,after))
                .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true).put("historical_creation_unknown",false)
                .put("business_dispatch_absent_in_original_receipts",false).put("foreign_dormant_history_preserved",true).put("cleanup_known",true)
                .put("automatic_resume",false).put("broker_release_response",false).put("profile_bootstrap_dispatched",true)
                .put("historical_broker_release_observed",true).put("model_action_dispatch_absent_in_original_receipts",true)
                .put("recorded_owned_identity",r.recordedOwnedIdentity());
    }
    private static void invalid(String name,Change change)throws Exception{no(name,()->{
        PublicProfileAbsenceRecovery.Request r=request(copy());JSONObject p=proof(r);change.change(p);PublicProfileAbsenceRecovery.validate(p,r,now+4025,boot);});}
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("exact archived inputs required");load(Paths.get(args[0]));
        yes("actual_postlaunch_originals_bind_exact_display_root_leaf",()->{PublicProfileAbsenceRecovery.Request r=request(copy());
            need(r.postlaunch&&r.displayId==196&&r.ownedRootTaskId==1455&&r.ownedLeafTaskId==1000010
                &&"a92355cf-c391-4698-9f02-5399765ee820".equals(r.ownedLeafTaskToken));});
        yes("actual_prefix_eof_false_is_not_final_exit_proof",()->{need(!object(originals.get("bootstrap")).getJSONObject("broker_output").getBoolean("eof_seen"));request(copy());});
        yes("new_typed_proof_accepts_with_synthetic_current_samples",()->{PublicProfileAbsenceRecovery.Request r=request(copy());PublicProfileAbsenceRecovery.validate(proof(r),r,now+4025,boot);});
        yes("canonical_wire_roundtrip_retains_exact_originals",()->{PublicProfileAbsenceRecovery.Request r=request(copy()),again=PublicProfileAbsenceRecovery.fromWire(r.wire());
            need(r.wire().length()+600<60000&&again.postlaunch&&again.originalsSha256.equals(r.originalsSha256));
            for(String key:originals.keySet())need(Arrays.equals(originals.get(key),again.original(key)));});
        no("old_prelaunch_factory_cannot_accept_postlaunch",()->PublicProfileAbsenceRecovery.request(copy(),controller(),10481,ID,now,boot));
        no("old_or_new_wrong_boot_rejects",()->PublicProfileAbsenceRecovery.postlaunchRequest(copy(),controller(),10481,ID,now,boot+1));
        no("before_original_ttl_rejects",()->PublicProfileAbsenceRecovery.postlaunchRequest(copy(),controller(),10481,ID,object(originals.get("journal")).getLong("expires_elapsed_ms"),boot));
        no("journal_wrong_display_rejects",()->request(change("journal",v->v.put("display_id",197))));
        no("journal_launch_false_rejects",()->request(change("journal",v->v.put("profile_launch_attempted",false))));
        no("public_scope_digest_changed_rejects",()->request(change("journal",v->v.put("public_own_group_scope_sha256",HASH))));
        no("final_exit_not_observed_rejects",()->request(change("cleanup",v->v.put("broker_process_exit_observed",false))));
        no("final_exit_nonzero_rejects",()->request(change("cleanup",v->v.put("broker_process_exit_code",70))));
        no("bootstrap_prefix_hash_changed_rejects",()->request(change("bootstrap",v->v.getJSONObject("broker_output").put("stored_sha256",HASH))));
        no("bootstrap_producer_changed_rejects",()->request(change("bootstrap",v->v.getJSONObject("broker_output").put("process_reference",1))));
        no("bootstrap_persisted_lie_rejects",()->request(change("bootstrap",v->v.getJSONObject("broker_output").put("persisted",true))));
        no("final_missing_eof_rejects",()->request(change("broker_receipt",v->v.put("eof_seen",false))));
        no("old_release_bytes_changed_rejects",()->request(change("broker_output",v->v.put("display_id",197))));
        no("model_process_started_rejects",()->request(change("result",v->v.getJSONObject("model_session").put("process_started",true))));
        no("model_steps_reject",()->request(change("result",v->v.put("steps",1))));
        no("tool_effect_attempt_rejects",()->request(change("result",v->v.getJSONArray("fixed_intent_attempts").put(new JSONObject()))));
        no("pending_permission_worker_rejects",()->request(change("result",v->v.put("profile_permission_preparation",new JSONObject()))));
        no("pending_action_worker_rejects",()->request(change("result",v->v.put("action_worker_pending_at_terminal",true))));
        invalid("v2_proof_is_not_postlaunch_authority",v->v.put("schema",PublicProfileAbsenceRecovery.SCHEMA));
        invalid("v2_source_is_not_postlaunch_authority",v->v.put("source",PublicProfileAbsenceRecovery.SOURCE));
        invalid("cannot_claim_historical_creation_unknown",v->v.put("historical_creation_unknown",true));
        invalid("cannot_claim_no_bootstrap_dispatch",v->v.put("business_dispatch_absent_in_original_receipts",true));
        invalid("historical_release_cannot_replace_current_absence",v->v.put("current_absence_verified",false));
        invalid("fresh_checker_cannot_claim_broker_close_response",v->v.put("broker_release_response",true));
        invalid("recorded_root_changed_rejects",v->v.getJSONObject("recorded_owned_identity").put("root_task_id",1456));
        invalid("recorded_leaf_token_changed_rejects",v->v.getJSONObject("recorded_owned_identity").put("leaf_task_token",ID));
        invalid("global_root_id_reused_by_other_user_rejects",v->v.getJSONObject("before").getJSONObject("live").getJSONArray("all_task_ids").put(0,1455));
        invalid("global_leaf_id_reused_by_other_user_rejects",v->v.getJSONObject("after").getJSONObject("live").getJSONArray("all_task_ids").put(0,1000010));
        for(int reused:new int[]{1455,1000010}){
            no("actual_live_primitive_rejects_user0_reused_id_"+reused,()->{
                PublicProfileAbsenceRecovery.Request r=request(copy());
                ProfileTaskPolicy.Root root=new ProfileTaskPolicy.Root(reused,0,0,0,false,null,null,new int[0],new int[0],new String[0],new int[0][]);
                ProfileTaskPolicy.Snapshot live=new ProfileTaskPolicy.Snapshot(Arrays.asList(root));live.requireDedicatedEmpty(r.target);
                r.requireRecordedLiveAbsent(live);
            });
            no("actual_recents_primitive_rejects_user0_reused_id_"+reused,()->{
                PublicProfileAbsenceRecovery.Request r=request(copy());
                String raw=before.replaceAll("(?<![0-9])1256(?![0-9])",Integer.toString(reused));
                PublicProfileRecentHistory.absence(raw,r.target); // Complete valid foreign history, not a malformed-input rejection.
                r.requireRecordedRecentsAbsent(raw);
            });
        }
        invalid("recorded_display_id_reused_rejects",v->v.getJSONObject("after").getJSONObject("displays").put("recorded_id_absent",false));
        invalid("old_creator_present_rejects",v->v.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
        invalid("incomplete_live_census_rejects",v->v.getJSONObject("before").getJSONObject("live").put("complete",false));
        invalid("physical_main_changed_rejects",v->v.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
        invalid("foreign_recent_raw_changed_rejects",v->v.getJSONObject("after").getJSONObject("recents").put("raw_text",after+"unknown"));
        invalid("current_apk_changed_rejects",v->v.getJSONObject("current_controller").put("source_sha256",ProfileIdentity.sha("other apk")));
        invalid("old_proof_request_replayed_rejects",v->v.put("request_id","77777777-7777-4777-8777-777777777777"));
        invalid("extra_proof_field_rejects",v->v.put("delete_foreign_tasks",true));
        no("expired_proof_rejects",()->{PublicProfileAbsenceRecovery.Request r=request(copy());PublicProfileAbsenceRecovery.validate(proof(r),r,r.deadline,boot);});
        System.out.println(new JSONObject().put("schema","hepta.public-postlaunch-host-tests.v1").put("all_pass",true).put("cases",names.length()).put("case_names",names)
                .put("actual_archived_failure_bytes",true).put("current_framework_clock_and_installation_synthetic",true)
                .put("phone_contacted",false).put("wire_bytes",request(copy()).wire().length()).put("proof_bytes",proof(request(copy())).toString().getBytes(StandardCharsets.UTF_8).length));
    }
}
