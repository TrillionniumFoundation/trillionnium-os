package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual 277631 history, complete Request and unchanged current-absence policy.
 * Only manifest stat/current-PM/clock and the separate startup control fixture are
 * synthetic. A classified failed history never proves current cleanup or business. */
public final class NativeSuccessRecoveryHostTest {
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private static PublicProfileBusinessRecoveryHostTest.Fixture original;
    private interface Work { void run()throws Exception; }
    private interface Change { void edit(PublicProfileBusinessRecoveryHostTest.Fixture f)throws Exception; }
    private static void need(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void pass(String name,Work work)throws Exception {work.run();CASES.put(new JSONObject().put("name",name).put("passed",true));}
    private static void reject(String name,String expected,Work work)throws Exception {
        try{work.run();}catch(Exception failure){
            String message=failure.getMessage();
            need(message!=null&&message.contains(expected),"wrong rejection "+name+": "+failure);
            CASES.put(new JSONObject().put("name",name).put("passed",true).put("actual_rejection_class",failure.getClass().getName()).put("actual_rejection",message));return;
        }
        throw new AssertionError("accepted "+name);
    }
    private static void changed(String name,String expected,Change change)throws Exception{
        reject(name,expected,()->{PublicProfileBusinessRecoveryHostTest.Fixture f=original.copy();change.edit(f);f.request();});
    }
    private static JSONObject result(PublicProfileBusinessRecoveryHostTest.Fixture f)throws Exception{return f.json(f.resultPath);}
    private static byte[] bytes(JSONObject object){return object.toString().getBytes(StandardCharsets.UTF_8);}
    private static String finalStep(PublicProfileBusinessRecoveryHostTest.Fixture f,String suffix)throws Exception{
        return f.taskPrefix+String.format(java.util.Locale.ROOT,"step-%02d-",result(f).getInt("steps"))+suffix;
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3)throw new IllegalArgumentException("manifest, exact original path map, new report");
        JSONObject report=new JSONObject().put("schema","hepta.native-success-recovery-policy-cases.v1").put("all_pass",false);
        Throwable failure=null;
        try{
            JSONObject manifest=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
            Map<String,byte[]> inputs=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
            original=new PublicProfileBusinessRecoveryHostTest.Fixture(manifest,inputs);
            pass("actual_complete_history_classifies_without_rewriting_terminal",()->{
                PublicProfileBusinessAbsenceRecovery.Request r=original.request();
                need(r.verifiedNativeSuccessBeforeCleanup&&r.retainedAfterBusiness&&!r.retainedBeforeFirstModel,"typed historical classification");
                need(r.steps==5&&r.modelRequests==5&&r.manifest.paths().size()==131,"actual complete input counts");
                JSONObject old=result(original),proof=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
                need(old.getBoolean("model_reported_success")&&!old.getBoolean("completion_verified")&&!old.getBoolean("cleanup_known"),"historical failure preserved");
                need(!old.getJSONObject("completion_evidence").getBoolean("business_verified")&&!old.getJSONObject("completion_evidence").getBoolean("terminal_binding_and_cleanup_verified"),"no new business authority");
                need(!proof.getBoolean("rewrites_business_outcome")&&!proof.getBoolean("historical_broker_release_observed"),"synthetic absence is separate");
                for(Map.Entry<String,byte[]> row:inputs.entrySet())need(Arrays.equals(row.getValue(),original.files.get(row.getKey())),"original input unchanged");
                TreeSet<String> actual=new TreeSet<String>();TreeMap<String,Integer> directories=new TreeMap<String,Integer>();
                for(String path:inputs.keySet())if(path.startsWith("runs/")){actual.add(path);String dir=path.substring(0,path.lastIndexOf('/'));
                    directories.put(dir,directories.containsKey(dir)?directories.get(dir)+1:1);}
                need(actual.size()==53&&directories.size()==6&&actual.equals(PublicProfileBusinessAbsenceRecovery.nativeSuccessModelPaths(old,inputs)),"all native members");
                for(Map.Entry<String,Integer> row:directories.entrySet())need(row.getValue()==(row.getKey().equals(original.modelPrefix.substring(0,original.modelPrefix.length()-1))?8:9),"exact per-directory member count");
                report.put("actual_task_members",r.manifest.taskFiles().size()).put("actual_native_members",actual.size()).put("historical_model_requests",r.modelRequests)
                    .put("original_terminal_completion_verified",old.getBoolean("completion_verified")).put("original_terminal_cleanup_known",old.getBoolean("cleanup_known"))
                    .put("original_broker_exit_observed",r.historicalBrokerExitObserved);
            });
            pass("startup_archive_preserves_same_success_history",()->{
                PublicProfileBusinessRecoveryHostTest.Fixture f=original.archived();
                PublicProfileBusinessAbsenceRecovery.Request r=f.request();
                need(r.verifiedNativeSuccessBeforeCleanup&&r.retainedAfterBusiness,"startup historical classification");
                need(Arrays.equals(original.files.get("control-session.json"),f.files.get(f.manifest.getString("origin_summary"))),"actual origin archived unchanged");
                need(!result(f).getBoolean("completion_verified")&&!result(f).getBoolean("cleanup_known"),"startup cannot complete old task");
            });
            changed("raw_input_hash_mismatch_refused","BUSINESS_INPUT_HASH",f->{byte[] b=f.files.get(f.resultPath).clone();b[b.length-1]^=1;f.files.put(f.resultPath,b);});
            changed("missing_generation_stdout_refused","NATIVE_SUCCESS_NATIVE_CLOSED_SET",f->f.remove(f.modelPrefix+"stdout.log"));
            changed("missing_request_grammar_refused","NATIVE_SUCCESS_NATIVE_CLOSED_SET",f->f.remove(f.firstAppRequest().replace("app-receipt.json","grammar.gbnf")));
            changed("extra_native_run_member_refused","NATIVE_SUCCESS_NATIVE_CLOSED_SET",f->f.put("runs/11111111111111111111111111111111/prompt.txt",new byte[]{1}));
            changed("old_false_model_branch_still_rejects_success_done","BUSINESS_MODEL_DISPOSITION",f->{JSONObject r=result(f);r.put("model_reported_success",false);f.result(r);});
            changed("success_flag_with_failure_disposition_refused","NATIVE_SUCCESS_MODEL_DISPOSITION",f->{JSONObject r=result(f);r.put("model_done_status","failure");f.result(r);});
            changed("unverified_final_model_claim_refused","model_success_claim_verified",f->{JSONObject r=result(f);r.getJSONObject("completion_evidence").put("model_success_claim_verified",false);f.result(r);});
            changed("unstable_preterminal_completion_refused","final_observation_stable",f->f.edit(finalStep(f,"completion-check.json"),o->o.put("final_observation_stable",false)));
            changed("other_model_run_completion_refused","NATIVE_SUCCESS_DONE_ACTION",f->f.edit(finalStep(f,"completion-check.json"),o->o.put("check_model_run_id","11111111111111111111111111111111")));
            changed("changed_final_ax_bytes_refused","NATIVE_SUCCESS_AX_BYTES",f->{String leaf=result(f).getJSONObject("completion_evidence").getJSONObject("public_native_result")
                    .getJSONObject("current_frame").getJSONObject("capture").getString("receipt_file");byte[] b=f.files.get(f.taskPrefix+leaf);
                byte[] other=Arrays.copyOf(b,b.length+1);other[b.length]=10;f.put(f.taskPrefix+leaf,other);});
            changed("foreign_task_terminal_refused","BUSINESS_TERMINAL",f->{JSONObject r=result(f);r.put("task_id","11111111111111111111111111111111");f.result(r);});
            changed("foreign_owner_record_refused","BUSINESS_OWNER",f->f.edit(f.taskPrefix+"owner.json",o->o.put("instruction_utf8_sha256",String.join("",java.util.Collections.nCopies(64,"a")))));
            changed("forged_cleanup_success_refused","cleanup_known",f->{JSONObject r=result(f);r.put("cleanup_known",true);f.result(r);});
            changed("forged_business_success_refused","business_verified",f->{JSONObject r=result(f);r.getJSONObject("completion_evidence").put("business_verified",true);f.result(r);});
            pass("original_expiry_and_deadline_fences_remain",()->{
                PublicProfileBusinessAbsenceRecovery.Request r=original.request();
                reject("request_before_expiry_grace_refused","BUSINESS_",()->r.requireFence(r.expires+1999,r.requestBoot));
                reject("request_at_deadline_refused","BUSINESS_",()->r.requireFence(r.deadline,r.requestBoot));
                reject("changed_current_boot_refused","BUSINESS_",()->r.requireFence(r.started,r.requestBoot+1));
            });
            report.put("all_pass",true);
        }catch(Throwable ex){failure=ex;report.put("failure_class",ex.getClass().getName()).put("failure",String.valueOf(ex));}
        report.put("cases",CASES.length()).put("assertions",assertions).put("case_results",CASES)
            .put("phone_operations",0).put("action_dispatches",0).put("actual_current_absence_observed",false).put("business_verified",false)
            .put("actual_android_runtime",false).put("synthetic_current_pm_stat_clock",true).put("old_failure_visual_zero_model_suites_executed",false);
        Files.write(Paths.get(args[2]),report.toString(2).getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(report.toString());
        if(failure instanceof Exception)throw (Exception)failure;if(failure instanceof Error)throw (Error)failure;
    }
}
