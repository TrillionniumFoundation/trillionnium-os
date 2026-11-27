package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Explicit synthetic normal-capture subset of the reviewed legacy harness.
 * Exercises the actual ordinary comparator and phase validator only; this is
 * not a complete Request, fresh-absence proof, Android IO, or cleanup authority. */
public final class PublicProfileNormalCaptureHostTest {
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private interface Work {void run()throws Exception;}
    private static void check(boolean b){assertions++;if(!b)throw new AssertionError("normal retained capture assertion");}
    private static void pass(String name,Work work)throws Exception{work.run();CASES.put(name);}
    private static void reject(String name,Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(IOException|JSONException expected){refused=true;}
        check(refused);CASES.put(name);
    }
    private static byte[] bytes(JSONObject j){return j.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject copy(JSONObject j){return new JSONObject(j.toString());}
    private static byte[] records(JSONObject a,JSONObject b){return (a.toString()+"\n"+b.toString()+"\n").getBytes(StandardCharsets.UTF_8);}
    private static String hash(String value)throws Exception{return ProfileIdentity.sha("synthetic-"+value);}
    private static final class Synthetic {
        final JSONObject journal,cleanup,result,first,second;
        byte[] override;
        Synthetic()throws Exception {
            String generation="11111111-2222-4333-8444-555555555555",scope=hash("scope"),target=hash("target");
            journal=new JSONObject().put("state","CLOSING").put("created_elapsed_ms",1000);
            JSONObject history=new JSONObject().put("schema","hepta.public-profile-history-custody.v2").put("target_sha256",target)
                .put("foreign_dormant_history_preserved",true).put("nonphysical_history_preserved",true).put("history_refusal_latched",false)
                .put("history_refusal_reason",JSONObject.NULL).put("history_preservation_scope","nonphysical_and_unresolved_recents")
                .put("physical_history_frozen",false).put("unrelated_physical_history_changes_observed",false).put("recents_presentation_changes_observed",false)
                .put("protected_history_sha256",hash("protected")).put("current_protected_history_sha256",hash("protected"))
                .put("baseline_elapsed_ms",1100).put("current_elapsed_ms",1900).put("baseline_raw_sha256",hash("baseline"))
                .put("current_raw_sha256",hash("before")).put("nonowned_history_sha256",hash("nonowned"))
                .put("baseline_task_ids",new JSONArray().put(12)).put("owned_task_ids",new JSONArray().put(90).put(91))
                .put("owned_target_absent",false).put("serialized_task_ids_grant_authority",false);
            JSONObject custody=new JSONObject().put("schema","hepta.profile-task-cleanup.v1").put("generation",generation).put("display_id",9)
                .put("target_sha256",target).put("user_id",10).put("user_serial",10).put("full_uid",1012345)
                .put("cleanup_known",false).put("live_tasks_absent",false).put("recents_tasks_absent",false).put("foreign_tasks_present",false).put("identity_unknown",false)
                .put("owned_tasks",new JSONArray().put(new JSONObject().put("task_id",91).put("parent_task_id",90)
                    .put("task_token_id","66666666-7777-4888-8999-aaaaaaaaaaaa").put("user_id",10).put("user_serial",10).put("full_uid",1012345)
                    .put("live_absent",false).put("recents_absent",false)))
                .put("public_foreign_recent_history",history).put("recents_absence_scope","owned_target_only_with_unrelated_physical_history_audited");
            JSONObject diagnostic=new JSONObject().put("schema","hepta.profile-cleanup-diagnostics.v1").put("first_failure",JSONObject.NULL)
                .put("diagnostics_grant_authority",false).put("provides_cleanup_proof",false).put("allows_input_or_model_resumption",false);
            first=new JSONObject().put("schema","hepta.background-broker-terminal.v1").put("generation",generation).put("state","CLEANUP_UNKNOWN")
                .put("display_id",9).put("reason","client_close").put("release_confirmed",false).put("boot_count_read_retirement_failure",JSONObject.NULL)
                .put("owned_single_task",JSONObject.NULL).put("profile_cleanup",copy(custody).put("identity_unknown",true))
                .put("profile_cleanup_diagnostics",copy(diagnostic).put("first_failure",new JSONObject().put("phase","TASK_RETIRE")
                    .put("code","PROFILE_CLEANUP_DEADLINE").put("observed_elapsed_ms",5100).put("cleanup_started_elapsed_ms",2000).put("task_reads_deadline_elapsed_ms",3400)))
                .put("profile_last_leaf_validation",new JSONObject().put("synthetic_identity",hash("leaf")))
                .put("profile_first_root_refusal",new JSONObject()).put("profile_permission_first_read_mismatch",new JSONObject())
                .put("profile_custody_retained",true).put("display_scope_sha256",scope).put("public_scope_admission_retired",true)
                .put("public_surface_detach",new JSONObject().put("synthetic_detach",true)).put("public_screen_lease",new JSONObject())
                .put("public_policy_diagnostics",new JSONObject());
            JSONObject close=copy(first);for(String k:new String[]{"schema","reason","release_confirmed","boot_count_read_retirement_failure","owned_single_task","public_screen_lease"})close.remove(k);
            close.put("state","CLOSING").put("operation","close").put("error","CLEANUP_NOT_CONFIRMED").put("terminal_reason","client_close")
                .put("ok",false).put("dispatched",false).put("profile_cleanup_known",false).put("public_scope_closing",true)
                .put("profile_cleanup",custody).put("profile_cleanup_diagnostics",diagnostic);
            cleanup=new JSONObject().put("state","CLOSING").put("last_broker_response",close);
            result=new JSONObject().put("status","blocked").put("steps",1).put("model_reported_success",false).put("cleanup_known",false)
                .put("completion_verified",false).put("external_model",false).put("last_action_execution",new JSONObject().put("worker_drained",true)
                    .put("callback_published",true).put("effect_entered",false).put("effect_returned",false).put("automatic_redispatch",false));
            second=copy(first);second.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history")
                .put("current_elapsed_ms",3000).put("current_raw_sha256",hash("after")).put("owned_target_absent",true);
            second.getJSONObject("profile_cleanup").put("normal_cleanup_phase",new JSONObject().put("schema","hepta.profile-normal-cleanup-phase.v1")
                .put("original_task_reads_deadline_elapsed_ms",3400).put("bounded_convergence_deadline_elapsed_ms",5000).put("maximum_census_to_effect_age_ms",1500)
                .put("read_convergence_activated",true).put("failed",true).put("last_sample_started_elapsed_ms",3100)
                .put("leaf_effect_entered_elapsed_ms",2100).put("leaf_effect_returned_elapsed_ms",2200)
                .put("root_effect_entered_elapsed_ms",-1).put("root_effect_returned_elapsed_ms",-1)
                .put("display_effect_entered_elapsed_ms",-1).put("display_effect_returned_elapsed_ms",-1)
                .put("business_admission_restored",false).put("serialized_evidence_is_authority",false));
        }
        JSONObject phase(){return second.getJSONObject("profile_cleanup").getJSONObject("normal_cleanup_phase");}
        JSONObject history(){return second.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history");}
    }
    private static JSONObject normalClose(Synthetic s)throws Exception {
        return copy(s.cleanup.getJSONObject("last_broker_response")).put("state","CLEANUP_UNKNOWN")
            .put("profile_cleanup",copy(s.second.getJSONObject("profile_cleanup")));
    }
    private static void syntheticNormalCapture()throws Exception {
        pass("synthetic_normal_complete_equal_phase_capture",()->{Synthetic s=new Synthetic();JSONObject close=normalClose(s);byte[] a=bytes(s.second),b=bytes(close);
            JSONObject fields=PublicProfileBusinessAbsenceRecovery.Request.retainedBusinessCaptureFields(s.second,close);
            check(!fields.has("normal_cleanup_phase"));check(Arrays.equals(a,bytes(s.second)));check(Arrays.equals(b,bytes(close)));});
        reject("synthetic_normal_phase_only_difference_refused_before_projection",()->{Synthetic s=new Synthetic();JSONObject close=normalClose(s);close.getJSONObject("profile_cleanup").getJSONObject("normal_cleanup_phase").put("failed",false);PublicProfileBusinessAbsenceRecovery.Request.retainedBusinessCaptureFields(s.second,close);});
        for(String key:new String[]{"unknown","failed","last_sample_started_elapsed_ms","business_admission_restored","serialized_evidence_is_authority"})
            reject("synthetic_normal_equal_invalid_phase_"+key,()->{Synthetic s=new Synthetic();s.phase().put(key,key.equals("failed")||key.equals("last_sample_started_elapsed_ms")?"invalid":Boolean.TRUE);PublicProfileBusinessAbsenceRecovery.Request.retainedBusinessCaptureFields(s.second,normalClose(s));});
        for(String key:new String[]{"profile_last_leaf_validation","public_surface_detach"})reject("synthetic_normal_full_equality_"+key,()->{Synthetic s=new Synthetic();JSONObject close=normalClose(s).put(key,new JSONObject().put("changed",true));PublicProfileBusinessAbsenceRecovery.Request.retainedBusinessCaptureFields(s.second,close);});
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=0)throw new IllegalArgumentException("synthetic normal capture takes no originals");
        syntheticNormalCapture();
        System.out.println(new JSONObject().put("schema","hepta.public-profile-normal-capture-host.v1")
            .put("passed",true).put("cases",CASES.length()).put("assertions",assertions).put("case_names",CASES)
            .put("fixture_kind","synthetic_normal_retained_capture").put("complete_request_executed",false)
            .put("actual_comparator_executed",true).put("private_originals_used",false).put("phone_commands",0));
    }
}
