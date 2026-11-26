package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual external task/core/native bytes; current stat/PM/clock/absence and
 * mutations are explicit host fixtures. No Android cleanup, input or CAS runs. */
public final class PublicProfileModelDoneCleanupHostTest {
    private static final JSONArray CASES=new JSONArray();
    private static int assertions,failures;
    private static PublicProfileBusinessRecoveryHostTest.Fixture original;
    private static final String SOURCE="fresh_public_profile_absence_after_verified_model_done_cleanup_failure";
    private static final String OTHER="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    interface Work {void run()throws Exception;}
    interface Change {void run(PublicProfileBusinessRecoveryHostTest.Fixture f)throws Exception;}
    private static void check(boolean yes){assertions++;if(!yes)throw new AssertionError("model-done cleanup assertion");}
    private static void run(String name,Work work){
        int start=assertions;
        try{work.run();CASES.put(new JSONObject().put("name",name).put("passed",true).put("assertions",assertions-start));}
        catch(Throwable e){failures++;CASES.put(new JSONObject().put("name",name).put("passed",false).put("assertions",assertions-start)
                .put("exception",e.getClass().getName()).put("detail",String.valueOf(e.getMessage())));}
    }
    private static void reject(String name,String code,Change change){
        run(name,()->{
            PublicProfileBusinessRecoveryHostTest.Fixture f=original.copy();change.run(f);
            try{f.request();throw new AssertionError("accepted changed model-done evidence");}
            catch(java.io.IOException e){check(code.isEmpty()||e.getMessage().contains(code));}
        });
    }
    private static JSONObject result(PublicProfileBusinessRecoveryHostTest.Fixture f)throws Exception{return f.json(f.resultPath);}
    private static String step(PublicProfileBusinessRecoveryHostTest.Fixture f,String suffix)throws Exception{
        return f.taskPrefix+String.format(java.util.Locale.ROOT,"step-%02d-",result(f).getInt("steps"))+suffix;
    }
    private static void terminal(PublicProfileBusinessRecoveryHostTest.Fixture f,String key,Object value)throws Exception{
        JSONObject r=result(f),c=r.getJSONObject("completion_evidence");c.put(key,value);
        if(c.getJSONObject("terminal_native_completion").has(key))c.getJSONObject("terminal_native_completion").put(key,value);
        f.result(r);
    }
    private static void proofReject(String name,PublicProfileBusinessRecoveryHostTest.Edit edit){
        run(name,()->{PublicProfileBusinessAbsenceRecovery.Request r=original.copy().request();
            JSONObject p=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);edit.run(p);
            try{PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);throw new AssertionError("accepted changed absence proof");}
            catch(java.io.IOException e){check(e.getMessage()!=null);}
            catch(org.json.JSONException e){check(e.getMessage()!=null);}
        });
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("manifest and external exact-original map required");
        JSONObject m=PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0])));
        Map<String,byte[]> files=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
        original=new PublicProfileBusinessRecoveryHostTest.Fixture(m,files);
        run("actual_model_done_cleanup_failed_typed_origin",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.copy().request();
            check(r.retainedAfterBusiness&&!r.retainedBeforeFirstModel&&r.retainedCurrentAbsenceRequired());
            check(SOURCE.equals(r.source())&&r.steps>0&&r.modelRequests>0);
            check(!r.historicalBrokerExitObserved&&r.historicalBrokerExitCode==null);
            JSONObject old=result(original);check(old.getBoolean("model_reported_success")&&!old.getBoolean("completion_verified")&&!old.getBoolean("cleanup_known"));
            check(!old.getJSONObject("completion_evidence").getBoolean("business_verified"));
            check(PublicProfileBusinessAbsenceRecovery.same(r.inputHashes(),original.request().inputHashes()));
        });
        run("synthetic_two_absence_samples_keep_failed_outcome",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.copy().request();
            JSONObject p=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
            JSONObject accepted=PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);
            check(accepted.getBoolean("cleanup_known")&&!accepted.getBoolean("rewrites_business_outcome"));
            check(!accepted.getBoolean("historical_broker_release_observed")&&!accepted.getBoolean("acknowledges_control_session"));
            check(!accepted.getBoolean("business_dispatch_absent_in_original_receipts")&&!accepted.getBoolean("automatic_resume"));
            check(accepted.getJSONObject("historical_broker_process").get("exit_code")==JSONObject.NULL);
        });
        run("startup_preserves_original_true_claim_and_failed_history",()->{
            PublicProfileBusinessRecoveryHostTest.Fixture f=original.archived();
            PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            check(SOURCE.equals(r.source())&&f.json("control-session.json").getString("status").equals("interrupted"));
            check(f.json(r.manifest.originSummary).getBoolean("model_reported_success"));
            check(!f.json(r.manifest.originSummary).getBoolean("completion_verified"));
            check(java.util.Arrays.equals(r.original(r.manifest.originSummary),original.files.get("control-session.json")));
            PublicProfileBusinessAbsenceRecovery.validate(PublicProfileBusinessRecoveryHostTest.syntheticProof(r),r,r.started+31,r.requestBoot);
        });
        run("request_does_not_rewrite_any_original",()->{
            PublicProfileBusinessRecoveryHostTest.Fixture f=original.copy();PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            r.archiveBytes();r.recordedOwnedIdentity();r.originalHistoryRefusal();r.historicalBrokerProcess();
            for(String p:files.keySet())check(java.util.Arrays.equals(files.get(p),r.original(p)));
            check(files.size()==f.files.size());
        });
        reject("success_claim_cannot_enter_incomplete_failure_branch","BUSINESS_MODEL_DISPOSITION",f->{JSONObject r=result(f);r.put("model_reported_success",false);f.result(r);});
        reject("failure_status_cannot_enter_new_branch","BUSINESS_MODEL_DONE_CLEANUP_KIND",f->{JSONObject r=result(f);r.put("model_done_status","failure");f.result(r);});
        reject("synthesized_model_done_refused","BUSINESS_EXPECTED_FALSE_model_done_synthesized",f->{JSONObject r=result(f);r.put("model_done_synthesized",true);f.result(r);});
        reject("controller_completion_claim_refused","BUSINESS_EXPECTED_FALSE_controller_completion_requested",f->{JSONObject r=result(f);r.put("controller_completion_requested",true);f.result(r);});
        reject("controller_actor_refused","BUSINESS_UNSUPPORTED_PENDING_CONTRACT",f->{JSONObject r=result(f);r.put("completion_actor","controller");f.result(r);});
        reject("historical_completion_cannot_be_upgraded","BUSINESS_EXPECTED_FALSE_completion_verified",f->{JSONObject r=result(f);r.put("completion_verified",true);f.result(r);});
        reject("historical_cleanup_cannot_be_upgraded","BUSINESS_EXPECTED_FALSE_cleanup_known",f->{JSONObject r=result(f);r.put("cleanup_known",true);f.result(r);});
        reject("goal_verified_claim_refused","BUSINESS_EXPECTED_FALSE_goal_independently_verified",f->{JSONObject r=result(f);r.put("goal_independently_verified",true);f.result(r);});
        reject("pending_action_refused","BUSINESS_EXPECTED_FALSE_action_worker_pending_at_terminal",f->{JSONObject r=result(f);r.put("action_worker_pending_at_terminal",true);f.result(r);});
        reject("undrained_final_action_refused","BUSINESS_EXPECTED_TRUE_worker_drained",f->{JSONObject r=result(f);r.getJSONObject("last_action_execution").put("worker_drained",false);f.result(r);});
        reject("done_effect_entered_refused","BUSINESS_EXPECTED_FALSE_effect_entered",f->{
            String p=step(f,"action.json");JSONObject a=f.json(p),e=a.getJSONObject("action_execution");e.put("effect_entered",true).put("effect_returned",true);f.put(p,a.toString().getBytes(StandardCharsets.UTF_8));
            JSONObject r=result(f);r.put("last_action_execution",e);f.result(r);
        });
        reject("model_summary_substitution_refused","BUSINESS_MODEL_DONE_ACTION",f->{JSONObject r=result(f);r.put("model_done_summary","different claim");f.result(r);});
        reject("different_done_model_run_refused","BUSINESS_MODEL_DONE_EXECUTION",f->f.edit(step(f,"action.json"),x->x.put("model_run_id",OTHER)));
        reject("dispatched_done_refused","BUSINESS_EXPECTED_FALSE_dispatched",f->f.edit(step(f,"action.json"),x->x.put("dispatched",true)));
        reject("stale_done_refused","BUSINESS_EXPECTED_FALSE_stale",f->f.edit(step(f,"action.json"),x->x.put("stale",true)));
        reject("independent_preclose_check_required","BUSINESS_EXPECTED_TRUE_completion_verified",f->f.edit(step(f,"completion-check.json"),x->x.put("completion_verified",false)));
        reject("check_step_bound","BUSINESS_MODEL_DONE_CHECK",f->f.edit(step(f,"completion-check.json"),x->x.put("check_step",1)));
        reject("check_identity_failure_refused","BUSINESS_MODEL_DONE_CHECK",f->f.edit(step(f,"completion-check.json"),x->x.put("identity_failure","moved")));
        reject("model_claim_independently_verified_required","BUSINESS_EXPECTED_TRUE_model_success_claim_verified",f->terminal(f,"model_success_claim_verified",false));
        reject("observation_chain_required","BUSINESS_EXPECTED_TRUE_observation_chain_verified",f->terminal(f,"observation_chain_verified",false));
        reject("normal_native_parent_binding_required","BUSINESS_EXPECTED_TRUE_native_normal0_parent_session_bound",f->terminal(f,"native_normal0_parent_session_bound",false));
        reject("installed_app_recheck_required","BUSINESS_EXPECTED_TRUE_installed_app_rechecked_after_cleanup",f->terminal(f,"installed_app_rechecked_after_cleanup",false));
        reject("terminal_business_success_refused","BUSINESS_EXPECTED_FALSE_business_verified",f->terminal(f,"business_verified",true));
        reject("cancelled_terminal_refused","BUSINESS_EXPECTED_FALSE_cancelled",f->terminal(f,"cancelled",true));
        reject("worker_receipt_bound","BUSINESS_MODEL_DONE_WORKER",f->terminal(f,"worker_receipt_sha256",new String(new char[64]).replace('\0','b')));
        reject("native_domain_must_be_retired","BUSINESS_EXPECTED_TRUE_action_domain_retired",f->f.edit(f.taskPrefix+"native-app-retired.json",x->x.put("action_domain_retired",false)));
        reject("native_pending_action_refused","BUSINESS_EXPECTED_FALSE_pending_action",f->f.edit(f.taskPrefix+"native-app-retired.json",x->x.put("pending_action",true)));
        reject("actual_after_observation_bound","BUSINESS_MODEL_DONE_FRAME_BINDING",f->f.edit(step(f,"after.json"),x->x.put("observation_id",OTHER)));
        reject("final_profile_window_bound","BUSINESS_MODEL_DONE_WINDOW",f->{JSONObject r=result(f);JSONObject c=r.getJSONObject("completion_evidence");c.getJSONObject("final_actual_profile_window").put("display_id",1);c.getJSONObject("terminal_native_completion").getJSONObject("final_actual_profile_window").put("display_id",1);f.result(r);});
        reject("current_control_claim_must_match","BUSINESS_EXPECTED_TRUE_model_reported_success",f->f.edit("control-session.json",x->x.put("model_reported_success",false)));
        reject("abnormal_native_close_refused","BUSINESS_MODEL_SESSION",f->{JSONObject x=f.json(f.sessionPath);x.put("exit_code",1);f.session(x);});
        proofReject("legacy_source_cannot_label_new_origin",p->p.put("source",PublicProfileBusinessAbsenceRecovery.RETAINED_BUSINESS_SOURCE));
        proofReject("historical_release_cannot_be_invented",p->p.put("historical_broker_release_observed",true));
        proofReject("original_business_outcome_not_rewritten",p->p.put("rewrites_business_outcome",true));
        proofReject("second_display_absence_required",p->p.getJSONObject("after").getJSONObject("displays").put("recorded_id_absent",false));
        proofReject("second_target_task_absence_required",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("target_task_ids").put(1));
        proofReject("same_boot_required",p->p.put("current_boot_count",p.getInt("current_boot_count")+1));
        proofReject("both_samples_firmware_bound",p->p.getJSONObject("after").put("firmware_fingerprint_sha256",new String(new char[64]).replace('\0','b')));
        JSONObject report=new JSONObject().put("schema","hepta.public-profile-model-done-cleanup-host.v1").put("passed",failures==0)
                .put("cases",CASES.length()).put("assertions",assertions).put("failures",failures).put("rows",CASES)
                .put("task_original_count",original.manifest.getJSONArray("task_membership").length()).put("all_original_count",files.size())
                .put("original_business_success_claimed",false).put("actual_android_absence_or_cas_executed",false)
                .put("fixture_boundary","Actual external original payloads; synthetic current clock/PM/stat, startup and two absence samples. Negative cases are derived mutations, never device evidence.");
        System.out.println(report.toString());
        if(failures!=0)System.exit(1);
    }
}
