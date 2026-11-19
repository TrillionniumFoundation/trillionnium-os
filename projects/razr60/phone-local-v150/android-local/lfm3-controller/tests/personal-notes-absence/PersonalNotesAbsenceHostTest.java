package org.trillionnium.hepta.background;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;
/** Authored values, synthetic clock and controller; no phone or Android runtime. */
public final class PersonalNotesAbsenceHostTest {
    private static int cases,assertions;
    private static final List<String> names=new ArrayList<String>();
    interface Work{void run()throws Exception;}
    interface Mutation{void run(JSONObject value)throws Exception;}
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);}
    private static void refuse(Work work)throws Exception{try{work.run();throw new AssertionError("unsafe input accepted");}catch(Exception expected){assertions++;}}
    private static JSONObject copy(JSONObject o){return new JSONObject(o.toString());}
    private static byte[] raw(JSONObject o){return o.toString().getBytes(StandardCharsets.UTF_8);}
    public static final class Fixture{
        public final String task="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",gen="11111111-2222-4333-8444-555555555555";
        public final String instruction="write a synthetic note",ownerHash=ProfileIdentity.sha(instruction),name="hepta-bg-"+gen;
        public final long created=1000,expires=541000,now=544000;public final int uid=12345,targetUid=23456,display=77,oldTask=400,boot=7;
        public final PublicOwnGroupPolicy.Scope scope=new PublicOwnGroupPolicy.Scope(task,ownerHash,gen,uid,null,created,expires,boot);
        public final Map<String,byte[]> inputs=new LinkedHashMap<String,byte[]>();public final JSONObject control,controller;
        public Fixture()throws Exception{
            JSONObject selection=new JSONObject().put("mode","background").put("bootstrap_package",PublicPersonalNotesAbsenceRecovery.PACKAGE)
                    .put("allowed_packages",new JSONArray().put(PublicPersonalNotesAbsenceRecovery.PACKAGE)).put("bootstrap_model_issued",false)
                    .put("main_display_fallback",false).put("home_allowed",false).put("display_scope_mode","public_own_group_personal_no_credentials_v1")
                    .put("display_scope_mode_source","immutable_start_selection").put("display_scope_mode_grants_authority",false);
            JSONObject journal=new JSONObject().put("schema","hepta.background-session.v1").put("task_id",task).put("app_uid",uid).put("owner_sha256",ownerHash)
                    .put("generation",gen).put("socket",name).put("display_name",name).put("display_id",display).put("state","CLEANUP_UNKNOWN")
                    .put("created_elapsed_ms",created).put("expires_elapsed_ms",expires).put("boot_count",boot).put("selection",selection)
                    .put("owned_task_retirement_required",true).put("personal_notes_retirement_required",true).put("public_own_group_experimental",true)
                    .put("public_scope_serialization_grants_authority",false).put("public_own_group_scope_wire",scope.wire()).put("public_own_group_scope_sha256",scope.sha256);
            JSONObject custody=new JSONObject().put("schema","hepta.public-personal-notes-cleanup.v1").put("generation",gen).put("scope_sha256",scope.sha256)
                    .put("package",PublicPersonalNotesAbsenceRecovery.PACKAGE).put("target_uid",targetUid).put("display_id",display)
                    .put("create_attempted",true).put("launch_dispatched",true).put("cleanup_known",false).put("actual_observed_tasks",new JSONArray())
                    .put("arbitrary_task_removal_used",false).put("force_stop_used",false).put("caller_flag_is_cleanup_proof",false);
            JSONObject terminal=new JSONObject().put("schema","hepta.background-broker-terminal.v1").put("generation",gen).put("display_id",display)
                    .put("state","CLEANUP_UNKNOWN").put("display_scope_sha256",scope.sha256).put("release_confirmed",false)
                    .put("public_scope_admission_retired",true).put("personal_notes_cleanup",custody);
            byte[] output=raw(terminal);
            JSONObject broker=new JSONObject().put("schema","hepta.background-broker-output.v1").put("task_id",task).put("generation",gen).put("app_uid",uid)
                    .put("app_pid",99).put("process_binding","owned_java_process_merged_stream").put("process_reference",123)
                    .put("command_sha256",ProfileIdentity.sha("synthetic command")).put("started_elapsed_ms",created+1).put("output_limit_bytes",65536)
                    .put("output_file","background-broker-"+gen+".bin").put("receipt_file","background-broker-"+gen+".json")
                    .put("eof_seen",false).put("read_failed",false).put("overflow",false).put("merged_stdout_stderr",true).put("model_input",false).put("release_evidence",false)
                    .put("persisted",true).put("stored_bytes",output.length).put("observed_bytes",output.length).put("stored_sha256",ProfileIdentity.sha(output));
            JSONObject location=new JSONObject().put("schema","hepta.public-own-group.task-location.v1").put("generation",gen).put("display_id",display)
                    .put("target_user_id",0).put("observed_owned_task_ids",new JSONArray().put(oldTask)).put("task_mutation_authority",false);
            JSONObject launch=new JSONObject().put("schema","hepta.background-task-launch-policy.v1").put("generation",gen).put("display_id",display)
                    .put("package",PublicPersonalNotesAbsenceRecovery.PACKAGE).put("target_uid",targetUid).put("component",PublicPersonalNotesAbsenceRecovery.PACKAGE+"/.Main")
                    .put("request_id","synthetic-launch").put("activity_info_rechecked_before_dispatch",true);
            JSONObject response=new JSONObject().put("version",BrokerProtocol.PUBLIC_OWN_GROUP_VERSION).put("generation",gen).put("display_id",display)
                    .put("display_scope_sha256",scope.sha256).put("personal_notes_cleanup",custody).put("public_task_location",location).put("task_launch_policy",launch)
                    .put("request_id","synthetic-launch");
            JSONObject bootstrap=copy(journal).put("retired",true).put("spawn_attempted",true).put("bootstrap_dispatched",true).put("bootstrap_model_issued",false)
                    .put("broker_process_exit_observed",false).put("broker_process_exit_code",JSONObject.NULL).put("broker_output",broker).put("last_broker_response",response);
            JSONObject cleanup=copy(bootstrap).put("cleanup_known",false).put("cleanup_error","synthetic original refusal");
            JSONObject authorization=new JSONObject().put("authorization_sha256",ProfileIdentity.sha("synthetic authorization"));
            JSONObject gate=copy(authorization).put("instruction_sha256",ownerHash).put("task_id",task).put("found_packages",new JSONArray()).put("last_check",new JSONObject());
            for(String k:new String[]{"discovery_run_id","opened_package","catalogue_sha256","discovery_observation_id","open_run_id","opened_observation_id","pending_open_package"})gate.put(k,JSONObject.NULL);
            JSONObject owner=new JSONObject().put("schema","hepta.local-owner.v1").put("task_id",task).put("instruction_utf8_sha256",ownerHash).put("instruction",instruction)
                    .put("background_request",selection).put("external_model",false).put("automatic_resume",false).put("task_authorization",authorization)
                    .put("task_authorization_sha256",authorization.get("authorization_sha256"));
            JSONObject model=new JSONObject().put("task_id",task).put("process_started",false).put("process_exit_observed",false).put("receipt_valid",true)
                    .put("worker_generation",JSONObject.NULL).put("exit_code",JSONObject.NULL).put("app_receipt_sha256",JSONObject.NULL);
            JSONObject nativeWork=new JSONObject().put("task_id",task).put("native_cleanup_known",true).put("run_id",JSONObject.NULL);
            for(String k:new String[]{"request_reserved","executor_accepted","worker_started","signal_entered","submission_unknown"})nativeWork.put(k,false);
            JSONObject result=new JSONObject().put("task_id",task).put("status","blocked").put("steps",0).put("submit_attempts",new JSONArray()).put("fixed_intent_attempts",new JSONArray())
                    .put("native_cancellation",nativeWork).put("model_session",model).put("background_cleanup",cleanup).put("background_session",bootstrap)
                    .put("task_authorization",gate).put("task_authorization_sha256",authorization.get("authorization_sha256")).put("terminal_decided_elapsed_ms",created+100);
            for(String k:new String[]{"cleanup_known","completion_verified","model_reported_success","external_model","automatic_replay","controller_completion_requested",
                    "observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})result.put(k,false);
            for(String k:new String[]{"last_action_execution","final_observation_id","model_done_status","completion_actor","profile_permission_preparation"})result.put(k,JSONObject.NULL);
            inputs.put("journal",raw(journal));inputs.put("owner",raw(owner));inputs.put("bootstrap",raw(bootstrap));inputs.put("cleanup",raw(cleanup));inputs.put("result",raw(result));inputs.put("broker_receipt",raw(broker));inputs.put("broker_output",output);
            control=new JSONObject().put("schema","hepta.local-session.v1").put("app_uid",uid).put("task_id",task).put("instruction_sha256",ownerHash)
                    .put("pending",false).put("running",false).put("blocked",true).put("automatic_resume",false);
            controller=new JSONObject().put("schema","hepta.recovery-controller-installation.v1").put("package","org.trillionnium.hepta.local").put("user_id",0)
                    .put("uid",uid).put("source_path","/data/app/synthetic/base.apk").put("source_bytes",12345).put("source_sha256",ProfileIdentity.sha("synthetic APK"))
                    .put("version_code",1).put("signer_sha256",new JSONArray().put(ProfileIdentity.sha("synthetic signer")));
        }
        public PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{return PublicPersonalNotesAbsenceRecovery.request(inputs,raw(control),controller,uid,"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",now,boot);}
        void mutate(String input,Mutation change)throws Exception{JSONObject o=new JSONObject(new String(inputs.get(input),StandardCharsets.UTF_8));change.run(o);inputs.put(input,raw(o));}
    }
    static String recents(int age){return PublicPhysicalAuditHostTest.recents(false).replace("    Activities=[]\n","    Activities=[]\n    lastActiveTime=2000 (inactive for "+age+"s)\n");}
    static JSONObject sample(PublicPersonalNotesAbsenceRecovery.Request r,long a,long b,int age)throws Exception{
        JSONObject process=new JSONObject().put("complete",true).put("old_creator_absent",true).put("started_elapsed_ms",a).put("finished_elapsed_ms",b)
                .put("self_pid",123).put("self_start_ticks",456).put("process_count",5).put("inspected_count",3).put("inventory_sha256",ProfileIdentity.sha("synthetic proc"));
        JSONObject root=new JSONObject().put("id",100).put("display",0).put("user",0).put("activities",1).put("visible",true).put("base","com.example/.Main").put("top","com.example/.Main");
        JSONObject leaf=new JSONObject().put("id",100).put("parent",100).put("display",0).put("user",0).put("name","com.example/.Main");
        JSONArray displays=new JSONArray();for(int id:new int[]{0,1})displays.put(new JSONObject().put("id",id).put("name","physical"+id).put("unique_id","local:"+id).put("flags",0).put("state",2));
        return new JSONObject().put("started_elapsed_ms",a).put("finished_elapsed_ms",b).put("process",process)
                .put("live",new JSONObject().put("complete",true).put("roots",new JSONArray().put(root)).put("leaves",new JSONArray().put(leaf)))
                .put("recents",new JSONObject(PublicPersonalNotesHistory.absence(recents(age),r).evidence()))
                .put("displays",new JSONObject().put("complete",true).put("rows",displays))
                .put("physical",new JSONObject().put("0",ProfileIdentity.sha("main")).put("1",ProfileIdentity.sha("cover")))
                .put("target_installation",new JSONObject().put("package",PublicPersonalNotesAbsenceRecovery.PACKAGE).put("uid",r.targetUid).put("source_path","/product/synthetic.apk").put("enabled",true));
    }
    public static JSONObject proof(PublicPersonalNotesAbsenceRecovery.Request r)throws Exception{return new JSONObject().put("schema",r.proofSchema()).put("source",r.source())
            .put("request_id",r.requestId).put("task_id",r.taskId).put("generation",r.generation).put("owner_uid",r.ownerUid).put("owner_sha256",r.ownerSha256)
            .put("journal_sha256",r.journalSha256).put("originals_sha256",r.originalsSha256).put("original_inputs",r.inputHashes())
            .put("public_scope_wire",r.publicScope.wire()).put("public_scope_sha256",r.publicScope.sha256).put("display_name",r.displayName)
            .put("recorded_owned_identity",r.recordedOwnedIdentity()).put("current_control_sha256",r.currentControlSha256).put("current_controller",r.controller())
            .put("old_boot_count",r.oldBoot).put("current_boot_count",r.requestBoot).put("lease_expires_elapsed_ms",r.expires).put("request_started_elapsed_ms",r.started)
            .put("started_elapsed_ms",r.started+1).put("finished_elapsed_ms",r.started+20).put("deadline_elapsed_ms",r.deadline)
            .put("before",sample(r,r.started+1,r.started+5,5)).put("after",sample(r,r.started+10,r.started+20,5))
            .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true).put("foreign_history_preserved",true).put("cleanup_known",true)
            .put("automatic_resume",false).put("broker_release_response",false).put("historical_broker_release_observed",false).put("business_success",false).put("rewrites_original_task_result",false);}
    static void badProof(String name,Mutation change)throws Exception{test(name,()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request r=f.request();JSONObject p=proof(r);change.run(p);
        refuse(()->PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot));});}
    public static void main(String[] args)throws Exception{
        test("dynamic synthetic identities and wire round trip",()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request r=f.request();
            yes(r.targetUid==f.targetUid&&r.recordedTaskIds.contains(f.oldTask)&&r.displayId==f.display,"dynamic binding");
            yes(PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire().equals(r.wire()),"roundtrip");});
        test("two complete absence samples preserve old failed outcome",()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request r=f.request();JSONObject p=proof(r);
            yes(PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot).getBoolean("cleanup_known"),"new absence");
            yes(!new JSONObject(new String(r.original("result"),StandardCharsets.UTF_8)).getBoolean("cleanup_known"),"old failure retained");
            yes(!new JSONObject(new String(r.original("cleanup"),StandardCharsets.UTF_8)).getBoolean("broker_process_exit_observed"),"old exit still unknown");});
        for(String key:new String[]{"steps","cleanup_known","completion_verified","model_reported_success","external_model","automatic_replay","observation_read_worker_pending_at_terminal","action_worker_pending_at_terminal","native_cancel_worker_pending_at_terminal"})
            test("original result refuses changed "+key,()->{Fixture f=new Fixture();f.mutate("result",j->j.put(key,"steps".equals(key)?1:true));refuse(()->f.request());});
        for(String key:new String[]{"task_id","owner_sha256","generation","display_id","app_uid","public_own_group_scope_wire"})
            test("original journal refuses changed "+key,()->{Fixture f=new Fixture();f.mutate("journal",j->j.put(key,"display_id".equals(key)?88:"app_uid".equals(key)?12346:"changed"));refuse(()->f.request());});
        test("current control task replacement refused",()->{Fixture f=new Fixture();f.control.put("task_id","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");refuse(()->f.request());});
        test("historical broker bytes remain exact",()->{Fixture f=new Fixture();f.inputs.put("broker_output",new byte[]{1});refuse(()->f.request());});
        test("scope type cannot become profile ten",()->{Fixture f=new Fixture();f.mutate("journal",j->j.put("profile_target_wire","anything"));refuse(()->f.request());});
        test("request snapshots original bytes",()->{Fixture f=new Fixture();PublicPersonalNotesAbsenceRecovery.Request r=f.request();byte[] kept=r.original("journal");f.inputs.get("journal")[0]=0;
            yes(Arrays.equals(kept,r.original("journal")),"input alias");});
        test("wire suffix refuses",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();refuse(()->PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()+"AA"));});
        for(String key:new String[]{"automatic_resume","broker_release_response","historical_broker_release_observed","business_success","rewrites_original_task_result"})
            badProof("positive proof refuses false authority "+key,p->p.put(key,true));
        badProof("main physical change refuses",p->p.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
        badProof("cover physical change refuses",p->p.getJSONObject("after").getJSONObject("physical").put("1",ProfileIdentity.sha("changed")));
        badProof("old display id reused refuses",p->p.getJSONObject("after").getJSONObject("displays").getJSONArray("rows").getJSONObject(1).put("id",77));
        badProof("old display name on another id refuses",p->p.getJSONObject("after").getJSONObject("displays").getJSONArray("rows").getJSONObject(1).put("name",p.get("display_name")));
        badProof("recorded task reused refuses",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("id",400));
        badProof("Notes moved to main refuses",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("roots").getJSONObject(0).put("top","com.motorola.stylus/.Main"));
        badProof("helper remains visible refuses",p->p.getJSONObject("after").getJSONObject("process").put("old_creator_absent",false));
        badProof("incomplete process census refuses",p->p.getJSONObject("after").getJSONObject("process").put("complete",false));
        badProof("changed installed UID refuses",p->p.getJSONObject("after").getJSONObject("target_installation").put("uid",23457));
        badProof("overlapping samples refuse",p->p.getJSONObject("after").put("started_elapsed_ms",544001));
        badProof("current control CAS changed refuses",p->p.put("current_control_sha256",ProfileIdentity.sha("replaced")));
        badProof("raw recents omitted refuses",p->p.getJSONObject("after").getJSONObject("recents").remove("raw_text"));
        test("Notes hidden history refuses",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();String raw=recents(5).replace("  Recent tasks:\n","mHiddenTasks=[Task{abc #999 type=standard A=23456:com.motorola.stylus}]\n  Recent tasks:\n");refuse(()->PublicPersonalNotesHistory.absence(raw,r));});
        test("full foreign body change refuses",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();PublicPersonalNotesHistory.Snapshot a=PublicPersonalNotesHistory.absence(recents(5),r);
            PublicPersonalNotesHistory.Snapshot b=PublicPersonalNotesHistory.absence(recents(5).replace("    Activities=[]","    Activities=[]\n    foreignFact=changed"),r);refuse(()->a.requireSameForeign(b,1));});
        test("bounded natural inactivity accepted",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();PublicPersonalNotesHistory.absence(recents(5),r).requireSameForeign(PublicPersonalNotesHistory.absence(recents(6),r),1);yes(true,"age only");});
        test("age reversal refuses",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();refuse(()->PublicPersonalNotesHistory.absence(recents(5),r).requireSameForeign(PublicPersonalNotesHistory.absence(recents(4),r),1));});
        test("deadline and boot remain strict",()->{PublicPersonalNotesAbsenceRecovery.Request r=new Fixture().request();refuse(()->r.requireFence(r.deadline,r.oldBoot));refuse(()->r.requireFence(r.started,r.oldBoot+1));});
        System.out.println(new JSONObject().put("schema","hepta.personal-notes-absence-host.v1").put("all_pass",true).put("cases",cases).put("assertions",assertions)
                .put("case_names",new JSONArray(names)).put("framework_fixtures_synthetic",true).put("phone_operations",0).put("android_runtime",false).put("business_success_claimed",false));
    }
}
