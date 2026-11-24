package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Actual archived failed business bytes; explicitly synthetic current system facts. */
public final class PublicProfileRetainedBusinessHostTest {
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private static PublicProfileBusinessRecoveryHostTest.Fixture original;
    interface Work {void run()throws Exception;}
    interface Edit {void edit(JSONObject value)throws Exception;}
    private PublicProfileRetainedBusinessHostTest(){}
    private static void check(boolean ok){assertions++;if(!ok)throw new AssertionError("retained business assertion");}
    private static void pass(String name,Work work)throws Exception{work.run();CASES.put(name);}
    private static void reject(String name,Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(IOException|JSONException expected){refused=true;}
        check(refused);CASES.put(name);
    }
    private static void proofReject(String name,Edit edit)throws Exception{
        PublicProfileBusinessAbsenceRecovery.Request r=original.request();
        JSONObject proof=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);edit.edit(proof);
        reject(name,()->PublicProfileBusinessAbsenceRecovery.validate(proof,r,r.started+31,r.requestBoot));
    }
    private static byte[] bytes(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static void replaceCleanup(PublicProfileBusinessRecoveryHostTest.Fixture f,JSONObject cleanup)throws Exception{
        f.put(f.taskPrefix+"background-cleanup.json",bytes(cleanup));
        JSONObject result=f.json(f.resultPath);result.put("background_cleanup",copy(cleanup));
        JSONObject session=copy(cleanup);session.remove("cleanup_known");session.remove("cleanup_error");result.put("background_session",session);
        f.put(f.resultPath,bytes(result));
    }
    /** Synthetic legal later failed Process observation; the old terminal remains UNKNOWN. */
    private static PublicProfileBusinessRecoveryHostTest.Fixture observedFailedExit(int code)throws Exception{
        PublicProfileBusinessRecoveryHostTest.Fixture f=original.copy();
        String generation=f.json("background-session.active.json").getString("generation");
        String brokerPath=f.taskPrefix+"background-broker-"+generation+".json";
        JSONObject broker=f.json(brokerPath);broker.put("eof_seen",true);f.put(brokerPath,bytes(broker));
        JSONObject cleanup=f.json(f.taskPrefix+"background-cleanup.json");
        cleanup.put("broker_process_exit_observed",true).put("broker_process_exit_code",code).put("broker_output",copy(broker));
        replaceCleanup(f,cleanup);return f;
    }
    public static void main(String[] args)throws Exception{
        JSONObject manifest=PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0])));
        Map<String,byte[]> inputs=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
        original=new PublicProfileBusinessRecoveryHostTest.Fixture(manifest,inputs);
        pass("actual_one_step_one_model_original_unknown_broker",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.request();
            check(r.retainedAfterBusiness&&!r.retainedBeforeFirstModel&&r.retainedCurrentAbsenceRequired());
            check(r.steps==1&&r.modelRequests==1&&!r.historicalBrokerExitObserved&&r.historicalBrokerExitCode==null);
            check(PublicProfileBusinessAbsenceRecovery.RETAINED_BUSINESS_SOURCE.equals(r.source()));
            check(r.originalHistoryRefusal().getBoolean("history_refusal_latched"));
            check("PUBLIC_HISTORY_PREVIOUS_REFUSAL".equals(r.originalHistoryRefusal().getString("history_refusal_reason")));
            check(!r.historicalBrokerProcess().getBoolean("normal_release_observed"));
        });
        pass("actual_startup_archive_keeps_old_failure",()->{
            PublicProfileBusinessAbsenceRecovery.Request direct=original.request(),archived=original.archived().request();
            check(archived.retainedAfterBusiness);check(PublicProfileBusinessAbsenceRecovery.same(direct.originalHistoryRefusal(),archived.originalHistoryRefusal()));
        });
        pass("current_double_absence_does_not_promote_old_broker",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.request();JSONObject p=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
            JSONObject verified=PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);
            check(verified.getBoolean("historical_model_exit_verified"));check(!verified.getBoolean("historical_broker_release_observed"));
            check(!verified.getBoolean("rewrites_business_outcome")&&!verified.getBoolean("acknowledges_control_session"));
            check(verified.getJSONObject("before").getJSONObject("displays").getBoolean("including_disabled"));
            check(PublicProfileBusinessAbsenceRecovery.same(r.originalHistoryRefusal(),verified.getJSONObject("original_history_refusal")));
        });
        for(int code:new int[]{70,137})pass("synthetic_later_failed_exit_"+code+"_still_not_release",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=observedFailedExit(code).request();
            check(r.retainedAfterBusiness&&r.historicalBrokerExitObserved&&r.historicalBrokerExitCode==code);
            check(!r.historicalBrokerProcess().getBoolean("normal_release_observed"));
            PublicProfileBusinessAbsenceRecovery.validate(PublicProfileBusinessRecoveryHostTest.syntheticProof(r),r,r.started+31,r.requestBoot);assertions++;
        });
        reject("exit_zero_cannot_relabel_unknown_terminal_as_release",()->observedFailedExit(0).request());
        reject("exit_outside_process_code_range",()->observedFailedExit(256).request());
        for(String field:new String[]{"historical_broker_release_observed","broker_release_response","rewrites_business_outcome","acknowledges_control_session","automatic_resume","business_dispatch_absent_in_original_receipts"})
            proofReject("false_history_or_authority_"+field,p->p.put(field,true));
        proofReject("model_exit_remains_mandatory",p->p.put("historical_model_exit_verified",false));
        proofReject("old_history_latch_cannot_be_cleared",p->p.getJSONObject("original_history_refusal").put("history_refusal_latched",false));
        proofReject("old_history_reason_cannot_be_rewritten",p->p.getJSONObject("original_history_refusal").put("history_refusal_reason","NONE"));
        proofReject("old_history_foreign_fact_cannot_be_upgraded",p->p.getJSONObject("original_history_refusal").put("nonphysical_history_preserved",true));
        proofReject("old_process_unknown_cannot_be_claimed_observed",p->p.getJSONObject("historical_broker_process").put("exit_observed",true));
        proofReject("old_process_nonzero_cannot_be_claimed_zero",p->p.getJSONObject("historical_broker_process").put("exit_code",0));
        proofReject("current_controller_must_match",p->p.getJSONObject("current_controller").put("source_sha256",ProfileIdentity.sha("other installed code")));
        proofReject("boot_must_still_match",p->p.put("current_boot_count",84));
        proofReject("firmware_must_match_double_sample",p->p.getJSONObject("after").put("firmware_fingerprint_sha256",ProfileIdentity.sha("other firmware")));
        proofReject("physical_main_preserved",p->p.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
        proofReject("physical_cover_preserved",p->p.getJSONObject("after").getJSONObject("physical").put("1",ProfileIdentity.sha("changed")));
        for(String when:new String[]{"before","after"}){
            proofReject(when+"_old_creator_present",p->p.getJSONObject(when).getJSONObject("process").put("old_creator_absent",false));
            proofReject(when+"_model_worker_present",p->p.getJSONObject(when).getJSONObject("process").put("model_worker_absent",false));
            proofReject(when+"_incomplete_process_census",p->p.getJSONObject(when).getJSONObject("process").put("complete",false));
            proofReject(when+"_incomplete_live_census",p->p.getJSONObject(when).getJSONObject("live").put("complete",false));
            proofReject(when+"_owned_root_still_live",p->p.getJSONObject(when).getJSONObject("live").getJSONArray("all_task_ids").put(1885));
            proofReject(when+"_target_live_task",p->p.getJSONObject(when).getJSONObject("live").getJSONArray("target_task_ids").put(1000076));
            proofReject(when+"_disabled_displays_not_included",p->p.getJSONObject(when).getJSONObject("displays").put("including_disabled",false));
            proofReject(when+"_display_id_still_present",p->p.getJSONObject(when).getJSONObject("displays").put("recorded_id_absent",false));
            proofReject(when+"_display_name_still_present",p->p.getJSONObject(when).getJSONObject("displays").put("exact_name_absent",false));
            proofReject(when+"_incomplete_display_census",p->p.getJSONObject(when).getJSONObject("displays").put("complete",false));
        }
        PublicProfileBusinessRecoveryHostTest.Fixture pending=original.copy();
        pending.edit(pending.resultPath,j->j.put("action_worker_pending_at_terminal",true));reject("actual_action_queue_must_be_drained",pending::request);
        PublicProfileBusinessRecoveryHostTest.Fixture missing=original.copy();missing.remove(missing.sessionPath);reject("actual_model_exit_receipt_required",missing::request);
        PublicProfileBusinessRecoveryHostTest.Fixture owner=original.copy();owner.edit(owner.taskPrefix+"owner.json",j->j.put("instruction","other task"));reject("old_owner_instruction_not_replaceable",owner::request);
        PublicProfileBusinessAbsenceRecovery.Request r=original.request();
        reject("deadline_not_extended",()->PublicProfileBusinessAbsenceRecovery.validate(PublicProfileBusinessRecoveryHostTest.syntheticProof(r),r,r.deadline,r.requestBoot));
        check(inputs.size()==original.files.size());
        for(Map.Entry<String,byte[]> entry:inputs.entrySet())check(java.util.Arrays.equals(entry.getValue(),original.files.get(entry.getKey())));
        System.out.println(new JSONObject().put("passed",true).put("cases",CASES.length()).put("assertions",assertions).put("case_names",CASES)
                .put("historical_original_files",inputs.size()).put("current_system_facts_synthetic",true).put("phone_current_absence_verified",false)
                .put("actual_policy_executed",true).put("phone_operations",0));
    }
}
