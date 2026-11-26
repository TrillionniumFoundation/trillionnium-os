package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest.Fixture;

/** Real 02d history bytes; current controller/stat/clock and double root samples
 * are explicit host boundaries. Mutants are separately named counterfactuals. */
public final class PublicProfileReleasedCloseHostTest {
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private static Fixture original;
    private interface Work {void run()throws Exception;}
    private interface Edit {void run(JSONObject value)throws Exception;}
    private PublicProfileReleasedCloseHostTest(){}
    private static void check(boolean ok){assertions++;if(!ok)throw new AssertionError("released-close policy boundary");}
    private static void pass(String name,Work work)throws Exception{work.run();CASES.put(name);}
    private static void reject(String name,String code,Work work)throws Exception{
        try{work.run();}catch(IOException|JSONException e){
            check(code.isEmpty()||e.getMessage()!=null&&e.getMessage().contains(code));CASES.put(name);return;
        }
        throw new AssertionError("accepted "+name);
    }
    private static byte[] bytes(JSONObject v){return v.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject copy(JSONObject v){return new JSONObject(v.toString());}
    private static String generation(Fixture f)throws Exception{return f.json(PublicProfileBusinessAbsenceRecovery.JOURNAL).getString("generation");}
    private static JSONObject cleanup(Fixture f)throws Exception{return f.json(f.taskPrefix+"background-cleanup.json");}
    private static void saveCleanup(Fixture f,JSONObject c)throws Exception{
        f.put(f.taskPrefix+"background-cleanup.json",bytes(c));
        JSONObject r=f.json(f.resultPath),session=copy(c);session.remove("cleanup_known");session.remove("cleanup_error");
        r.put("background_cleanup",copy(c)).put("background_session",session);f.result(r);
    }
    /** Rehash all changed host-counterfactual bytes; never edit archived originals. */
    private static void closed(Fixture f,Edit lastEdit,Edit terminalEdit)throws Exception{
        JSONObject c=cleanup(f);lastEdit.run(c.getJSONObject("last_broker_response"));
        if(terminalEdit!=null){
            String base=f.taskPrefix+"background-broker-"+generation(f);
            JSONObject terminal=f.json(base+".bin");terminalEdit.run(terminal);
            byte[] out=(terminal.toString()+"\n").getBytes(StandardCharsets.UTF_8);f.put(base+".bin",out);
            JSONObject broker=f.json(base+".json").put("stored_bytes",out.length).put("observed_bytes",out.length).put("stored_sha256",ProfileIdentity.sha(out));
            f.put(base+".json",bytes(broker));c.put("broker_output",copy(broker));
        }
        saveCleanup(f,c);
    }
    private static void cleanupEdit(Fixture f,Edit edit)throws Exception{
        closed(f,last->edit.run(last.getJSONObject("profile_cleanup")),terminal->edit.run(terminal.getJSONObject("profile_cleanup")));
    }
    private static void phase(Fixture f,Edit edit)throws Exception{
        cleanupEdit(f,value->edit.run(value.getJSONObject("normal_cleanup_phase")));
    }
    private static void proofReject(String name,Edit edit)throws Exception{
        PublicProfileBusinessAbsenceRecovery.Request r=original.request();
        JSONObject proof=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);edit.run(proof);
        reject(name,"",()->PublicProfileBusinessAbsenceRecovery.validate(proof,r,r.started+31,r.requestBoot));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("manifest and complete original path map required");
        Map<String,byte[]> inputs=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
        original=new Fixture(PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0]))),inputs);
        pass("actual_02d_complete_released_close_is_history_only",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.request();
            check(r.taskId.equals("02d27deccfce45eaacd15003203e321a")&&inputs.size()==76&&r.manifest.taskFiles().size()==58);
            check(r.steps==4&&r.modelRequests==4&&r.displayId==717&&r.target.profile.userId==10);
            check(r.historicalBrokerExitObserved&&r.historicalBrokerExitCode==0&&!r.retainedCurrentAbsenceRequired()
                    &&!r.retainedBeforeFirstModel&&!r.retainedAfterBusiness&&!r.retainedModelDoneCleanupFailure);
            check(ProfileIdentity.sha(r.task("result.json")).equals("e6f4a1043df290b1064e59f98511113f9607e3bae768ff04d24f2ec0d16161c9"));
            JSONObject result=original.json(original.resultPath);
            check(result.getString("status").equals("blocked")&&!result.getBoolean("cleanup_known")&&!result.getBoolean("model_reported_success"));
            for(Map.Entry<String,byte[]> e:inputs.entrySet())check(Arrays.equals(e.getValue(),r.original(e.getKey())));
        });
        pass("actual_startup_archive_preserves_same_old_failed_result",()->{
            Fixture archived=original.archived();PublicProfileBusinessAbsenceRecovery.Request r=archived.request();
            check(!r.retainedCurrentAbsenceRequired()&&Arrays.equals(r.task("result.json"),inputs.get(original.resultPath)));
            check(Arrays.equals(r.original(archived.manifest.getString("origin_summary")),inputs.get("control-session.json")));
        });
        pass("new_double_absence_is_still_required_and_never_ack_or_business_pass",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.request();
            JSONObject p=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
            JSONObject accepted=PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);
            check(accepted.getBoolean("current_absence_verified")&&accepted.getBoolean("historical_broker_release_observed"));
            check(!accepted.getBoolean("rewrites_business_outcome")&&!accepted.getBoolean("acknowledges_control_session")
                    &&!accepted.getBoolean("automatic_resume")&&!accepted.getBoolean("broker_release_response"));
        });
        pass("optional_phase_absent_does_not_change_complete_release_requirements",()->{
            Fixture f=original.copy();cleanupEdit(f,v->v.remove("normal_cleanup_phase"));check(!f.request().retainedCurrentAbsenceRequired());
        });
        reject("unknown_phase_key_rejected","RECOVERY_FIELDS_DIFFER",()->{
            Fixture f=original.copy();phase(f,v->v.put("unexpected",true));f.request();
        });
        for(String key:new String[]{"maximum_census_to_effect_age_ms","original_task_reads_deadline_elapsed_ms","last_sample_started_elapsed_ms"})
            reject("phase_integer_type_"+key,"RECOVERY_INTEGER_",()->{
                Fixture f=original.copy();phase(f,v->v.put(key,"1500"));f.request();
            });
        reject("phase_1500_bound_is_exact","BUSINESS_RELEASED_PHASE_SHAPE",()->{
            Fixture f=original.copy();phase(f,v->v.put("maximum_census_to_effect_age_ms",1501));f.request();
        });
        reject("phase_boolean_type_is_exact","BUSINESS_RELEASED_PHASE_SHAPE",()->{
            Fixture f=original.copy();phase(f,v->v.put("failed","false"));f.request();
        });
        for(String key:new String[]{"business_admission_restored","serialized_evidence_is_authority"})
            reject("phase_cannot_grant_"+key,"BUSINESS_EXPECTED_FALSE_"+key,()->{
                Fixture f=original.copy();phase(f,v->v.put(key,true));f.request();
            });
        reject("phase_time_below_minus_one_rejected","BUSINESS_RELEASED_PHASE_CLOCK",()->{
            Fixture f=original.copy();phase(f,v->v.put("display_effect_entered_elapsed_ms",-2));f.request();
        });
        reject("unknown_cleanup_field_rejected","RECOVERY_FIELDS_DIFFER",()->{
            Fixture f=original.copy();cleanupEdit(f,v->v.put("unexpected",false));f.request();
        });
        reject("terminal_and_close_complete_phase_must_match","BUSINESS_RELEASED_CLOSE_TERMINAL_BINDING",()->{
            Fixture f=original.copy();closed(f,v->v.getJSONObject("profile_cleanup").getJSONObject("normal_cleanup_phase").put("failed",true),null);f.request();
        });
        reject("last_response_must_be_same_close_generation","BUSINESS_RELEASED_CLOSE_RESPONSE",()->{
            Fixture f=original.copy();closed(f,v->v.put("generation","11111111-2222-4333-8444-555555555555"),null);f.request();
        });
        reject("release_confirmed_false_never_history_success","BUSINESS_EXPECTED_TRUE_release_confirmed",()->{
            Fixture f=original.copy();closed(f,v->{},v->v.put("release_confirmed",false));f.request();
        });
        reject("foreign_tasks_cannot_be_hidden_by_phase","BUSINESS_EXPECTED_FALSE_foreign_tasks_present",()->{
            Fixture f=original.copy();cleanupEdit(f,v->v.put("foreign_tasks_present",true));f.request();
        });
        reject("identity_unknown_cannot_be_hidden_by_phase","BUSINESS_EXPECTED_FALSE_identity_unknown",()->{
            Fixture f=original.copy();cleanupEdit(f,v->v.put("identity_unknown",true));f.request();
        });
        reject("owned_token_must_match_original_launch","BUSINESS_OWNED_IDENTITY_CHANGED",()->{
            Fixture f=original.copy();cleanupEdit(f,v->v.getJSONArray("owned_tasks").getJSONObject(0).put("task_token_id","11111111-2222-4333-8444-555555555555"));f.request();
        });
        reject("eof_false_refuses_before_history_admission","PUBLIC_RECOVERY_BROKER_TRANSPORT",()->{
            Fixture f=original.copy();String p=f.taskPrefix+"background-broker-"+generation(f)+".json";JSONObject b=f.json(p).put("eof_seen",false);
            f.put(p,bytes(b));JSONObject c=cleanup(f).put("broker_output",b);saveCleanup(f,c);f.request();
        });
        reject("failed_broker_exit_cannot_relabel_release","",()->{
            Fixture f=original.copy();JSONObject c=cleanup(f).put("broker_process_exit_code",137);saveCleanup(f,c);f.request();
        });
        reject("model_success_not_admitted_by_this_release_branch","BUSINESS_EXPECTED_FALSE_model_reported_success",()->{
            Fixture f=original.copy();f.result(f.json(f.resultPath).put("model_reported_success",true));f.request();
        });
        reject("pending_action_still_rejected","BUSINESS_EXPECTED_FALSE_action_worker_pending_at_terminal",()->{
            Fixture f=original.copy();f.result(f.json(f.resultPath).put("action_worker_pending_at_terminal",true));f.request();
        });
        reject("original_expiry_grace_is_unchanged","BUSINESS_BOOT_TTL_OR_DEADLINE",()->{
            Fixture f=original.copy();f.manifest.put("started_elapsed_ms",f.json("background-session.active.json").getLong("expires_elapsed_ms")+2000);f.request();
        });
        reject("boot_is_unchanged","BUSINESS_BOOT_TTL_OR_DEADLINE",()->{
            Fixture f=original.copy();f.manifest.put("boot_count",84);f.request();
        });
        reject("twelve_second_fresh_deadline_not_extended","BUSINESS_BOOT_TTL_OR_DEADLINE",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=original.request();r.requireFence(r.deadline,r.requestBoot);
        });
        proofReject("fresh_creator_absence_mandatory",p->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
        proofReject("fresh_owned_task_absence_mandatory",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("all_task_ids").put(2127));
        proofReject("fresh_complete_census_mandatory",p->p.getJSONObject("before").getJSONObject("live").put("complete",false));
        proofReject("physical_main_comparison_mandatory",p->p.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
        proofReject("physical_cover_comparison_mandatory",p->p.getJSONObject("after").getJSONObject("physical").put("1",ProfileIdentity.sha("changed")));
        proofReject("absence_cannot_acknowledge",p->p.put("acknowledges_control_session",true));
        for(Map.Entry<String,byte[]> e:inputs.entrySet())check(Arrays.equals(e.getValue(),original.files.get(e.getKey())));
        System.out.println(new JSONObject().put("passed",true).put("cases",CASES.length()).put("assertions",assertions).put("case_names",CASES)
                .put("original_files",76).put("original_task_files",58).put("original_model_files",16).put("original_core_files",2)
                .put("recorded_steps",4).put("recorded_model_requests",4).put("original_bytes_unchanged",true)
                .put("actual_policy_executed",true).put("current_controller_stat_clock_and_root_samples_synthetic",true)
                .put("phone_current_absence_verified",false).put("phone_operations",0));
    }
}
