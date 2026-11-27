package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest.Fixture;

/** Real complete ce5 originals, actual Request/archive/proof consumer.
 * PM/stat/current clock/root observations are explicit host boundaries.
 * No retained socket, key, Phone effect, lease removal or ACK executes here. */
public final class PublicProfileClosingRecoveryHostTest {
    interface Work { void run() throws Exception; }
    interface Edit { void run(JSONObject value) throws Exception; }
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private static Fixture original;
    private static Map<String,byte[]> inputs;
    private static String brokerBin,brokerJson;
    private static void check(boolean ok,String reason) {
        assertions++;if(!ok)throw new AssertionError(reason);
    }
    private static JSONObject object(byte[] value)throws Exception{return PublicProfileBusinessAbsenceRecovery.object(value);}
    private static byte[] bytes(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject copy(JSONObject value)throws Exception{return object(bytes(value));}
    private static void pass(String name,Work body)throws Exception{
        int before=assertions;
        try{body.run();CASES.put(new JSONObject().put("name",name).put("status","PASS").put("assertions",assertions-before));}
        catch(Exception|AssertionError e){CASES.put(new JSONObject().put("name",name).put("status","FAIL").put("assertions",assertions-before).put("error",e.toString()));throw e;}
    }
    private static void reject(String name,Work body)throws Exception{
        pass(name,()->{
            try{body.run();}
            catch(Exception e){
                check(e instanceof IOException,"semantic refusal required; fixture/runtime error is not a pass: "+e);
                check(e.getMessage()!=null&&!e.getMessage().isEmpty(),"refusal must carry a reason");
                return;
            }
            throw new AssertionError("accepted forbidden closing recovery: "+name);
        });
    }
    private static JSONObject[] terminals(Fixture f)throws Exception{
        String[] lines=new String(f.files.get(brokerBin),StandardCharsets.UTF_8).split("\n",-1);
        check(lines.length==3&&lines[2].isEmpty(),"full actual two-terminal fixture");
        return new JSONObject[]{new JSONObject(lines[0]),new JSONObject(lines[1])};
    }
    private static void result(Fixture f,JSONObject value)throws Exception{
        f.put(f.resultPath,bytes(value));
        JSONObject c=f.json("control-session.json");
        if(c.has("task_result_reference")){
            JSONObject d=f.manifest.getJSONObject("files").getJSONObject(f.resultPath);
            c.getJSONObject("task_result_reference").put("bytes",d.getLong("bytes")).put("sha256",d.getString("sha256"));
        }else{
            c.put("completion_evidence",copy(value.getJSONObject("completion_evidence"))).put("state",value.get("summary"));
            for(String k:new String[]{"status","steps","completion_verified","goal_independently_verified","model_reported_success",
                    "cleanup_known","external_model","expected_scope_sha256","actual_scope_sha256"})c.put(k,value.get(k));
        }
        f.put("control-session.json",bytes(c));
    }
    private static void cleanup(Fixture f,JSONObject value)throws Exception{
        f.put(f.taskPrefix+"background-cleanup.json",bytes(value));
        JSONObject r=f.json(f.resultPath),session=copy(value);session.remove("cleanup_known");session.remove("cleanup_error");
        r.put("background_cleanup",copy(value)).put("background_session",session);result(f,r);
    }
    private static void output(Fixture f,byte[] value)throws Exception{
        f.put(brokerBin,value);
        JSONObject b=f.json(brokerJson).put("stored_bytes",value.length).put("observed_bytes",value.length).put("stored_sha256",ProfileIdentity.sha(value));
        f.put(brokerJson,bytes(b));
        JSONObject c=f.json(f.taskPrefix+"background-cleanup.json").put("broker_output",copy(b));cleanup(f,c);
    }
    private static void output(Fixture f,JSONObject first,JSONObject second)throws Exception{
        output(f,(first.toString()+"\n"+(second==null?"":second.toString()+"\n")).getBytes(StandardCharsets.UTF_8));
    }
    private static Fixture terminalEdit(int which,Edit edit)throws Exception{
        Fixture f=original.copy();JSONObject[] t=terminals(f);edit.run(t[which]);output(f,t[0],t[1]);return f;
    }
    private static Fixture bothTerminalEdit(Edit edit)throws Exception{
        Fixture f=original.copy();JSONObject[] t=terminals(f);edit.run(t[0]);edit.run(t[1]);output(f,t[0],t[1]);return f;
    }
    private static PublicProfileBusinessAbsenceRecovery.Request actual()throws Exception{
        try{return original.request();}
        catch(IOException failure){throw new AssertionError("actual_ce5_complete_CLOSING_history_must_admit_only_retained_recovery: "+failure.getMessage(),failure);}
    }
    private static byte[] block(DataInputStream in)throws Exception{
        int n=in.readInt();check(n>=0&&n<=PublicProfileBusinessAbsenceRecovery.MAX_BUNDLE,"archive block bound");
        byte[] b=new byte[n];in.readFully(b);return b;
    }
    private static JSONObject fresh(PublicProfileBusinessAbsenceRecovery.Request r)throws Exception{
        return PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
    }
    private static void proofReject(String name,Edit edit)throws Exception{
        reject(name,()->{PublicProfileBusinessAbsenceRecovery.Request r=actual();JSONObject p=fresh(r);edit.run(p);
            PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);});
    }
    private static void tests()throws Exception{
        pass("actual_ce5_complete_originals_enter_retained_request_without_rewriting_failure",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=actual();
            check(inputs.size()==29&&r.manifest.taskFiles().size()==20&&r.steps==1&&r.modelRequests==1,"full actual input and model counts");
            check(r.retainedAfterBusiness&&!r.retainedBeforeFirstModel&&!r.retainedModelDoneCleanupFailure,"only completed-model retained cleanup");
            check(!r.historicalBrokerExitObserved&&r.historicalBrokerExitCode==null,"unobserved broker exit preserved");
            check(r.ownedRootTaskId==2203&&r.ownedLeafTaskId==1000119&&r.displayId==781,"actual owned identities");
            check("CLOSING".equals(object(r.original("background-session.active.json")).getString("state")),"old CLOSING journal preserved");
            check(r.task("background-broker-"+r.generation+".bin").length==11334,"whole two-record byte length");
            check("41dc7715aa7e7516a56bac7737dbb6c9a4a2ef621bfc5414e00c57c311d14b9f".equals(ProfileIdentity.sha(r.task("background-broker-"+r.generation+".bin"))),"actual complete broker bytes");
            for(String p:inputs.keySet())check(Arrays.equals(inputs.get(p),r.original(p)),"full original retained: "+p);
            JSONObject[] t=terminals(original);
            check(!PublicProfileBusinessAbsenceRecovery.same(t[0],t[1]),"two actual records must remain different");
            check(!t[0].getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").getBoolean("owned_target_absent")
                    &&t[1].getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").getBoolean("owned_target_absent"),"actual later history not promoted");
        });
        pass("full_binary_archive_preserves_all_29_originals_and_original_CLOSING_bytes",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=actual();
            try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(r.archiveBytes()))){
                check("hepta.public-profile-business-originals.v1".equals(in.readUTF()),"archive schema");
                check(Arrays.equals(block(in),PublicProfileBusinessAbsenceRecovery.canonical(r.manifest.json()).getBytes(StandardCharsets.UTF_8)),"full manifest bytes");
                int count=in.readInt();check(count==inputs.size(),"all originals archived");TreeSet<String> seen=new TreeSet<String>();
                for(int i=0;i<count;i++){String p=in.readUTF();check(seen.add(p),"unique path");check(Arrays.equals(block(in),inputs.get(p)),"whole archived original "+p);}
                check(in.read()==-1&&seen.equals(inputs.keySet()),"exact EOF and membership");
            }
        });
        pass("bounded_manifest_roundtrip_does_not_change_full_originals",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=actual();
            PublicProfileBusinessAbsenceRecovery.Manifest m=PublicProfileBusinessAbsenceRecovery.fromWire(r.wire());
            PublicProfileBusinessAbsenceRecovery.Request other=PublicProfileBusinessAbsenceRecovery.request(m,inputs);
            check(r.manifest.sha256.equals(m.sha256)&&r.originalsSha256.equals(other.originalsSha256),"same wire/originals identities");
        });
        pass("request_defensive_copies_keep_original_history",()->{
            Fixture f=original.copy();PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            f.files.get(brokerBin)[0]^=1;byte[] got=r.task("background-broker-"+r.generation+".bin");got[0]^=1;
            check(Arrays.equals(inputs.get(brokerBin),r.task("background-broker-"+r.generation+".bin")),"defensive copies");
        });
        pass("same_task_archived_startup_chain_retains_CLOSING_origin",()->{
            Fixture f=original.archived();PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            check(r.retainedAfterBusiness&&r.taskId.equals(original.task)&&f.manifest.getString("origin_summary").startsWith("session-recovery/"),"same complete startup archive");
        });
        pass("single_complete_close_bound_terminal_remains_a_supported_history",()->{
            Fixture f=original.copy();byte[] raw=f.files.get(brokerBin);int end=0;while(raw[end]!='\n')end++;
            output(f,Arrays.copyOf(raw,end+1));PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            check(r.retainedAfterBusiness&&r.task("background-broker-"+r.generation+".bin").length==end+1,"full one record remains history");
        });
        pass("two_complete_equal_records_keep_original_supported_grammar",()->{
            Fixture f=original.copy();JSONObject[] t=terminals(f);output(f,t[0],t[0]);
            check(f.request().retainedAfterBusiness,"exact two equal full records");
        });
        pass("future_local_UNKNOWN_keeps_raw_CLOSING_reply_and_actual_two_records",()->{
            Fixture f=original.copy();f.edit("background-session.active.json",v->v.put("state","CLEANUP_UNKNOWN"));
            JSONObject c=f.json(f.taskPrefix+"background-cleanup.json").put("state","CLEANUP_UNKNOWN");cleanup(f,c);
            PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            check(r.retainedAfterBusiness&&"CLEANUP_UNKNOWN".equals(object(r.original("background-session.active.json")).getString("state")),"future local retirement state");
            check("CLOSING".equals(object(r.task("background-cleanup.json")).getJSONObject("last_broker_response").getString("state")),"raw response not rewritten");
            check(Arrays.equals(inputs.get(brokerBin),r.task("background-broker-"+r.generation+".bin")),"full raw broker output unchanged");
        });
        pass("legacy_UNKNOWN_exact_two_record_contract_still_runs",()->{
            Fixture f=original.copy();JSONObject[] t=terminals(f);
            f.edit("background-session.active.json",v->v.put("state","CLEANUP_UNKNOWN"));
            JSONObject c=f.json(f.taskPrefix+"background-cleanup.json").put("state","CLEANUP_UNKNOWN");
            c.getJSONObject("last_broker_response").put("state","CLEANUP_UNKNOWN").put("profile_cleanup",copy(t[0].getJSONObject("profile_cleanup")));
            cleanup(f,c);output(f,t[0],t[0]);
            check(f.request().retainedAfterBusiness,"old full equality branch still admitted as history");
        });
        pass("fresh_double_absence_is_separate_and_does_not_ACK_or_resume_business",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=actual();JSONObject p=fresh(r);
            JSONObject accepted=PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);
            check(accepted.getBoolean("cleanup_known")&&!accepted.getBoolean("broker_release_response"),"new absence only");
            check(!accepted.getBoolean("acknowledges_control_session")&&!accepted.getBoolean("automatic_resume")
                    &&!accepted.getBoolean("rewrites_business_outcome"),"no ACK/resume/outcome rewrite");
            check(!accepted.getBoolean("historical_broker_release_observed"),"old broker release remains unconfirmed");
            check(Arrays.equals(inputs.get(brokerBin),r.task("background-broker-"+r.generation+".bin")),"fresh proof never rewrites history");
        });
        reject("missing_native_original_is_not_replaced_by_terminal_summary",()->{
            Fixture f=original.copy();f.remove(f.modelPrefix+"native-session-result.json");f.request();
        });
        reject("original_byte_hash_tamper_rejects_before_origin",()->{
            Fixture f=original.copy();f.files.get(brokerBin)[10]^=1;f.request();
        });
        reject("ACTIVE_journal_is_not_recovery_admission",()->{
            Fixture f=original.copy();f.edit("background-session.active.json",v->v.put("state","ACTIVE"));f.request();
        });
        reject("CLOSING_requires_original_retained_socket_binding",()->{
            Fixture f=original.copy();f.edit("background-session.active.json",v->v.put("retained_cleanup_socket","hepta-retained-wrong"));f.request();
        });
        reject("CLOSING_requires_same_original_task",()->{
            Fixture f=original.copy();f.edit("background-session.active.json",v->v.put("task_id","11111111111111111111111111111111"));f.request();
        });
        reject("expiry_grace_boundary_is_not_passed",()->{
            Fixture f=original.copy();f.manifest.put("started_elapsed_ms",f.json("background-session.active.json").getLong("expires_elapsed_ms")+2000);f.request();
        });
        reject("other_boot_cannot_reuse_retained_origin",()->{
            Fixture f=original.copy();f.manifest.put("boot_count",f.manifest.getInt("boot_count")+1);f.request();
        });
        reject("empty_output_rejects_even_with_rehashed_receipt",()->{Fixture f=original.copy();output(f,new byte[0]);f.request();});
        reject("partial_last_line_rejects_even_with_rehashed_receipt",()->{Fixture f=original.copy();byte[] raw=f.files.get(brokerBin);output(f,Arrays.copyOf(raw,raw.length-1));f.request();});
        reject("third_complete_terminal_rejects",()->{Fixture f=original.copy();JSONObject[] t=terminals(f);output(f,(t[0]+"\n"+t[1]+"\n"+t[1]+"\n").getBytes(StandardCharsets.UTF_8));f.request();});
        reject("CR_record_boundary_rejects",()->{Fixture f=original.copy();output(f,new String(f.files.get(brokerBin),StandardCharsets.UTF_8).replace("\n","\r\n").getBytes(StandardCharsets.UTF_8));f.request();});
        reject("changed_second_generation_rejects",()->terminalEdit(1,t->t.put("generation","11111111-1111-4111-8111-111111111111")).request());
        reject("unknown_terminal_field_rejects",()->bothTerminalEdit(t->t.put("host_unknown_authority",true)).request());
        reject("second_terminal_cannot_claim_release",()->terminalEdit(1,t->t.put("release_confirmed",true)).request());
        reject("second_history_cannot_change_protected_history_identity",()->terminalEdit(1,t->t.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("protected_history_sha256",new String(new char[64]).replace('\0','a'))).request());
        reject("second_history_requires_single_new_failed_phase",()->terminalEdit(1,t->t.getJSONObject("profile_cleanup").remove("normal_cleanup_phase")).request());
        reject("second_history_clock_must_be_later",()->terminalEdit(1,t->t.getJSONObject("profile_cleanup").getJSONObject("public_foreign_recent_history").put("current_elapsed_ms",1117034182L)).request());
        reject("new_phase_must_remain_failed_not_cleanup_success",()->terminalEdit(1,t->t.getJSONObject("profile_cleanup").getJSONObject("normal_cleanup_phase").put("failed",false)).request());
        reject("new_phase_cannot_claim_root_effect_started",()->terminalEdit(1,t->t.getJSONObject("profile_cleanup").getJSONObject("normal_cleanup_phase").put("root_effect_entered_elapsed_ms",1117037000L)).request());
        reject("new_phase_must_bind_same_first_failure_deadline",()->terminalEdit(1,t->t.getJSONObject("profile_cleanup").getJSONObject("normal_cleanup_phase").put("original_task_reads_deadline_elapsed_ms",1117036630L)).request());
        reject("unknown_transition_requires_actual_cleanup_deadline_failure",()->bothTerminalEdit(t->t.getJSONObject("profile_cleanup_diagnostics").getJSONObject("first_failure").put("code","HOST_DIFFERENT_FAILURE")).request());
        reject("unknown_transition_cannot_promote_diagnostics_to_authority",()->bothTerminalEdit(t->t.getJSONObject("profile_cleanup_diagnostics").put("diagnostics_grant_authority",true)).request());
        reject("unknown_transition_cannot_change_other_cleanup_flags",()->bothTerminalEdit(t->t.getJSONObject("profile_cleanup").put("foreign_tasks_present",true)).request());
        reject("unknown_transition_is_not_true_to_false",()->{
            Fixture f=original.copy();JSONObject[] t=terminals(f);for(JSONObject v:t)v.getJSONObject("profile_cleanup").put("identity_unknown",false);
            JSONObject c=f.json(f.taskPrefix+"background-cleanup.json");c.getJSONObject("last_broker_response").getJSONObject("profile_cleanup").put("identity_unknown",true);
            cleanup(f,c);output(f,t[0],t[1]);f.request();
        });
        reject("wrong_close_operation_cannot_enter_closing_history",()->{
            Fixture f=original.copy();JSONObject c=f.json(f.taskPrefix+"background-cleanup.json");c.getJSONObject("last_broker_response").put("operation","click");cleanup(f,c);f.request();
        });
        reject("pending_action_worker_cannot_enter_recovery",()->{
            Fixture f=original.copy();JSONObject r=f.json(f.resultPath).put("action_worker_pending_at_terminal",true);result(f,r);f.request();
        });
        reject("historical_failed_CLOSING_does_not_become_exit_zero",()->{
            Fixture f=original.copy();JSONObject c=f.json(f.taskPrefix+"background-cleanup.json").put("broker_process_exit_observed",true).put("broker_process_exit_code",0);cleanup(f,c);f.request();
        });
        reject("fresh_request_expiry_remains_original_twelve_seconds",()->{PublicProfileBusinessAbsenceRecovery.Request r=actual();r.requireFence(r.deadline,r.requestBoot);});
        proofReject("fresh_proof_cannot_acknowledge_control",p->p.put("acknowledges_control_session",true));
        proofReject("fresh_proof_cannot_resume_task",p->p.put("automatic_resume",true));
        proofReject("fresh_proof_cannot_claim_old_broker_release",p->p.put("historical_broker_release_observed",true));
        proofReject("second_historical_absence_is_not_current_display_absence",p->p.getJSONObject("after").getJSONObject("displays").put("recorded_id_absent",false));
        proofReject("fresh_proof_must_keep_complete_live_task_inventory",p->p.getJSONObject("after").getJSONObject("live").put("complete",false));
        proofReject("fresh_proof_must_keep_exact_old_creator_absence",p->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
        proofReject("fresh_proof_must_keep_two_distinct_temporal_reads",p->{
            p.put("after",copy(p.getJSONObject("before")));
        });
        proofReject("fresh_proof_must_bind_current_controller",p->p.getJSONObject("current_controller").put("source_sha256",new String(new char[64]).replace('\0','b')));
        proofReject("fresh_proof_cannot_rewrite_original_history",p->p.put("original_history_refusal",new JSONObject()));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3)throw new IllegalArgumentException("manifest, original paths, output");
        inputs=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
        original=new Fixture(object(Files.readAllBytes(Paths.get(args[0]))),inputs);
        String gen=original.json("background-session.active.json").getString("generation");
        brokerBin=original.taskPrefix+"background-broker-"+gen+".bin";brokerJson=original.taskPrefix+"background-broker-"+gen+".json";
        Throwable failed=null;try{tests();}catch(Throwable e){failed=e;}
        JSONObject result=new JSONObject().put("schema","hepta.ce5.closing-request-host.v1").put("status",failed==null?"PASS":"FAIL")
                .put("cases",CASES.length()).put("assertions",assertions).put("rows",CASES).put("input_count",inputs.size())
                .put("actual_originals_unchanged",true).put("current_pm_stat_clock_and_absence_are_host_boundaries",true)
                .put("retained_socket_executed",false).put("phone_operations",0).put("acknowledgement_executed",false);
        Path output=Paths.get(args[2]);Files.write(output,bytes(result),StandardOpenOption.CREATE_NEW);
        System.out.println(new JSONObject().put("status",result.get("status")).put("cases",CASES.length()).put("assertions",assertions));
        if(failed!=null){failed.printStackTrace(System.err);System.exit(1);}
    }
}
